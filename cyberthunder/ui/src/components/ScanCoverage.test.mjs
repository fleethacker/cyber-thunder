import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluate, mount, text, ui } from '../lib/contentTestSupport.mjs';

const sample = () => ({ version: 1, target_id: 'rhel9', asset_type: 'linux', simulated: false,
  phase: 'preflight', complete: false, applicability: { status: 'inferred', observed_at: '2026-11-04', age_seconds: 90000 },
  products: [{ product_key: 'RHEL_9', library_url: '/content?tab=browse&product=RHEL_9',
    manual: { status: 'not_downloaded', count: 0 }, scap: { status: 'recorded', count: 1 } }],
  native: { status: 'configured_unverified' }, scanner: { engine: 'openscap', location: 'target', status: 'unknown',
    content_status: 'unknown', applicability: 'unverified', observed_at: '2026-11-04', age_seconds: 90000, stale: true },
  warnings: ['The held ZIP does not establish host readiness.'],
  actions: [{ label: 'Download or import content', href: '/content?tab=transfers' }] });

const format = { fmtAgo: (value) => `age(${value})`, fmtTime: (value) => value };
test('coverage keeps manual holdings, SCAP holdings and host capability distinct', async () => {
  const Component = evaluate(new URL('./ScanCoverage.tsx', import.meta.url), {
    '@mantine/core': ui, 'react-router-dom': { Link: 'Link' }, '../lib/format': format,
  }).ScanCoverage;
  const panel = mount(() => Component, { coverage: sample() }); await panel.settle();
  const rendered = panel.nodes().map(text).join('\n');
  assert.match(rendered, /Manual guide: not downloaded/);
  assert.match(rendered, /SCAP download: recorded/);
  assert.match(rendered, /SCAP engine: openscap on target · unknown/);
  assert.match(rendered, /stale or configuration changed/);
  assert.match(rendered, /Incomplete or unverified/);
  assert.ok(panel.nodes().some((n) => n.props?.to === '/content?tab=browse&product=RHEL_9'));
  assert.ok(panel.nodes().some((n) => n.props?.to === '/content?tab=transfers'));
  panel.unmount();
});
test('legacy runs show unknown coverage rather than clean', async () => {
  const Component = evaluate(new URL('./ScanCoverage.tsx', import.meta.url), {
    '@mantine/core': ui, 'react-router-dom': { Link: 'Link' }, '../lib/format': format,
  }).ScanCoverage;
  const panel = mount(() => Component); await panel.settle();
  assert.ok(panel.nodes().some((n) => text(n).includes('Coverage unknown'))); panel.unmount();
});

function preflightPanel(read) {
  return mount((hooks) => evaluate(new URL('./ScanContentPreflight.tsx', import.meta.url), {
    react: hooks, '@mantine/core': ui, '../api/client': { errorText: (e) => e.message },
    '../api/scanContent': { scanPreflight: read }, './ScanCoverage': { ScanCoverage: 'ScanCoverage' },
  }).ScanContentPreflight, { targetIds: ['rhel9'], modules: ['check'] });
}
test('mount and refresh only request local preflight; downloads remain explicit links', async () => {
  const calls = [];
  const panel = preflightPanel(async (...args) => { calls.push(args); return { targets: [sample()] }; });
  await panel.settle(); await panel.click('Refresh local coverage');
  assert.deepEqual(calls, [[['rhel9'], ['check']], [['rhel9'], ['check']]]);
  assert.ok(panel.nodes().some((n) => text(n).includes('does not download STIGs or install scanners')));
  assert.equal(panel.nodes().filter((n) => n.type === 'ScanCoverage').length, 1);
  panel.unmount();
});
test('changed target selection rejects late responses from the previous selection', async () => {
  const pending = [];
  const panel = preflightPanel((ids) => new Promise((resolve) => pending.push({ ids, resolve })));
  await panel.settle(); await panel.rerender({ targetIds: ['new-host'], modules: ['check'] });
  pending[1].resolve({ targets: [{ ...sample(), target_id: 'new-host' }] }); await panel.settle();
  pending[0].resolve({ targets: [sample()] }); await panel.settle();
  assert.equal(panel.find((n) => n.type === 'ScanCoverage').props.coverage.target_id, 'new-host');
  panel.unmount();
});
test('preflight read failure shows unknown and hides any previous coverage', async () => {
  let fail = false;
  const panel = preflightPanel(async () => { if (fail) throw new Error('unavailable'); return { targets: [sample()] }; });
  await panel.settle(); fail = true; await panel.click('Refresh local coverage');
  assert.ok(panel.nodes().some((n) => n.props?.title === 'Coverage unknown'));
  assert.ok(!panel.nodes().some((n) => n.type === 'ScanCoverage')); panel.unmount();
});
test('no selected module does not send an implicit default scan query', async () => {
  let calls = 0;
  const panel = preflightPanel(async () => { calls++; return { targets: [] }; });
  await panel.settle(); await panel.rerender({ targetIds: [], modules: [] });
  assert.equal(calls, 1);
  assert.equal(panel.button('Refresh local coverage').props.disabled, true); panel.unmount();
});
test('client encodes repeated target IDs and sends only GET', async () => {
  const calls = [];
  const { scanPreflight } = evaluate(new URL('../api/scanContent.ts', import.meta.url), {
    './client': { request: (...args) => { calls.push(args); return Promise.resolve({}); } },
  });
  await scanPreflight(['host one', 'other&host'], ['check', 'hunt']);
  assert.equal(calls[0][0], 'GET');
  const url = new URL(calls[0][1], 'http://local');
  assert.deepEqual(url.searchParams.getAll('target_ids'), ['host one', 'other&host']);
  assert.deepEqual(url.searchParams.getAll('modules'), ['check', 'hunt']);
});
