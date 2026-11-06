import assert from 'node:assert/strict';
import test from 'node:test';
import { browser, errorText, format, mount, text, ui } from '../lib/contentTestSupport.mjs';
import { createModuleLoader } from '../lib/moduleTestSupport.mjs';

const page = (changes = {}) => ({ findings: [], total: 403, unfiltered_total: 410, offset: 0, scan_id: 'base',
  facets: { confidence: [], review: [], reassessment: [
    { value: 'not_reassessed', label: 'Not reassessed', count: 203 },
    { value: 'no_known_gap', label: 'No known gap', count: 200 }, { value: 'unknown', label: 'Unknown', count: 7 },
  ] }, ...changes });
const account = (subject) => ({ mode: 'oidc', authenticated: true, permissions: ['read'],
  principal: { issuer: 'https://identity.example.test', subject, actor: subject, roles: ['viewer'] } });

function findings(t, { identity = null, respond = async () => page() } = {}) {
  const load = createModuleLoader(), requests = [];
  load(new URL('../api/identity.ts', import.meta.url)).setSessionIdentity(identity);
  const panel = mount((hooks) => {
    load(new URL('../lib/hooks.ts', import.meta.url), { react: hooks, '../api/client': { errorText } });
    return load(new URL('./Findings.tsx', import.meta.url), {
      react: hooks, '@mantine/core': ui, '@mantine/hooks': { useDebouncedValue: (value) => [value] },
      '@mantine/notifications': { notifications: { show() {} } },
      '../api/client': { errorText, api: { findings: async (query) => { requests.push(query); return respond(query); } } },
      '../components/common': ui, '../components/FindingDrawer': ui, '../components/FindingAssurance': ui,
      '../components/FindingReassessment': ui, '../lib/format': format,
    }).default;
  });
  t.after(() => panel.unmount());
  return { panel, requests, latest: () => requests.at(-1) };
}

test('reassessment controls send combined API queries, reset pagination, and keep server counts', async (t) => {
  browser(t);
  const { panel, latest } = findings(t);
  await panel.settle();
  assert.deepEqual(panel.control('Reassessment').props.data.map((o) => o.label),
    ['Not reassessed (203)', 'No known gap (200)', 'Unknown (7)']);
  assert.match(text(panel.nodes()), /No known gap does not establish freshness, complete coverage or a current pass/);
  const body = panel.find((n) => n.type === 'AsyncView').props.children(page());
  panel.nodes(body).find((n) => n.type === 'Pagination').props.onChange(3);
  await panel.settle(); assert.equal(latest().offset, 400);
  await panel.change('Reassessment', ['not_reassessed', 'unknown']);
  assert.equal(latest().offset, 0);
  assert.equal(latest().reassessment, '"not_reassessed","unknown"');
  assert.equal(latest().status, '"open"');
  assert.equal(panel.button('All open').props['aria-pressed'], false);
  await panel.change('Search findings', 'SSH');
  await panel.change('Evidence confidence', ['low']);
  await panel.change('Human review', ['unreviewed']);
  await panel.change('Sort by', 'observed_at');
  await panel.change('Direction', 'desc');
  assert.equal(latest().q, 'SSH'); assert.equal(latest().confidence, '"low"');
  assert.equal(latest().review, '"unreviewed"'); assert.equal(latest().sort_by, 'observed_at');
  assert.equal(latest().sort_dir, 'desc');
  assert.match(text(panel.nodes()), /403 matching \/ 410 total results/);
  assert.ok(panel.control('Sort by').props.data.some((o) => o.value === 'collected_at' && o.label === 'Collection time'));
  await panel.click('Clear filters');
  assert.equal(latest().reassessment, ''); assert.equal(latest().sort_by, 'observed_at');
  assert.equal(latest().status, ''); assert.equal(latest().q, '');
  await panel.change('Reassessment', ['no_known_gap']);
  await panel.click('Open STIGs');
  assert.equal(latest().reassessment, ''); assert.equal(latest().category, '"stig"');
  await panel.click('Reset defaults');
  assert.equal(latest().sort_by, 'default'); assert.equal(latest().sort_dir, 'asc');
  assert.equal(latest().status, '"open"'); assert.equal(latest().category, '');
});

test('preferences survive remount per account without inheriting another account or dev filters', async (t) => {
  browser(t);
  localStorage.setItem('ct.f.host', '["dev-secret-host"]');
  let first = findings(t, { identity: account('first') }); await first.panel.settle();
  assert.equal(first.latest().host, '');
  await first.panel.change('Machine', ['alpha']);
  await first.panel.change('Reassessment', ['not_reassessed']);
  await first.panel.change('Sort by', 'observed_at');
  await first.panel.change('Direction', 'desc');
  first.panel.unmount();
  const second = findings(t, { identity: account('second') }); await second.panel.settle();
  assert.equal(second.latest().host, ''); assert.equal(second.latest().reassessment, '');
  assert.equal(second.latest().sort_by, 'default');
  assert.doesNotMatch(text(second.panel.nodes()), /alpha|dev-secret-host/);
  first = findings(t, { identity: account('first'), respond: async () => page({ facets: { confidence: [], review: [], reassessment: [] } }) });
  await first.panel.settle();
  assert.equal(first.latest().host, '"alpha"'); assert.equal(first.latest().reassessment, '"not_reassessed"');
  assert.equal(first.latest().sort_by, 'observed_at'); assert.equal(first.latest().sort_dir, 'desc');
  assert.deepEqual(first.panel.control('Reassessment').props.data, [{ value: 'not_reassessed', label: 'Not reassessed (0)' }]);
  await first.panel.click('Reset defaults'); first.panel.unmount();
  const reset = findings(t, { identity: account('first') }); await reset.panel.settle();
  assert.equal(reset.latest().reassessment, ''); assert.equal(reset.latest().sort_by, 'default');
});

test('missing server capability pauses saved filters/sorts and never infers reassessment from rows', async (t) => {
  browser(t);
  localStorage.setItem('ct.f.reassessment', '["unknown"]');
  localStorage.setItem('ct.f.sort', '"observed_at"');
  const legacy = findings(t, { respond: async () => page({ facets: { confidence: [], review: [] },
    findings: [{ reassessment: { status: 'not_reassessed' } }] }) });
  await legacy.panel.settle();
  assert.equal(legacy.panel.control('Reassessment').props.disabled, true);
  assert.equal(legacy.latest().reassessment, undefined); assert.equal(legacy.latest().sort_by, 'default');
  assert.equal(localStorage.getItem('ct.f.reassessment'), '["unknown"]');
  assert.match(text(legacy.panel.nodes()), /Reassessment filtering and observation-time sorting are unavailable/);
  legacy.panel.unmount();
  const upgraded = findings(t); await upgraded.panel.settle();
  assert.equal(upgraded.latest().reassessment, '"unknown"'); assert.equal(upgraded.latest().sort_by, 'observed_at');
});

test('malformed saved preferences and inherited property names cannot change query objects or labels', async (t) => {
  browser(t);
  localStorage.setItem('ct.f.reassessment', '["__proto__"]');
  localStorage.setItem('ct.f.sort', '"constructor"');
  localStorage.setItem('ct.f.host', '{"__proto__":{"polluted":true}}');
  localStorage.setItem('ct.f.category', '["constructor"]');
  const { panel, latest } = findings(t); await panel.settle();
  assert.equal(latest().reassessment, ''); assert.equal(latest().host, ''); assert.equal(latest().sort_by, 'default');
  assert.deepEqual(panel.control('Category').props.data, [{ value: 'constructor', label: 'constructor (0)' }]);
  assert.equal({}.polluted, undefined);
  assert.equal(Object.getPrototypeOf(latest()), Object.prototype);
});

test('late queries and unmounted account results cannot replace the current view', async (t) => {
  browser(t);
  let release;
  const first = findings(t, { identity: account('first'), respond: (query) => query.reassessment === '"not_reassessed"'
    ? new Promise((resolve) => { release = resolve; }) : Promise.resolve(page()) });
  await first.panel.settle(); await first.panel.change('Reassessment', ['not_reassessed']);
  await first.panel.change('Reassessment', ['unknown']);
  release(page({ total: 987, unfiltered_total: 987 })); await first.panel.settle();
  assert.doesNotMatch(text(first.panel.nodes()), /987 matching/);
  await first.panel.change('Reassessment', ['not_reassessed']); first.panel.unmount();
  const second = findings(t, { identity: account('second'), respond: async () => page({ total: 1, unfiltered_total: 1 }) });
  await second.panel.settle(); release(page({ total: 987, unfiltered_total: 987 })); await second.panel.settle();
  assert.match(text(second.panel.nodes()), /1 matching \/ 1 total results/);
  assert.equal(second.latest().reassessment, '');
});

test('the real client encodes the query and rejects findings decoded after account authority changes', async (t) => {
  const oldFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = oldFetch; });
  let requested, release;
  globalThis.fetch = async (url) => {
    requested = url;
    return { ok: true, headers: new Headers({ 'Content-Type': 'application/json' }),
      json: () => new Promise((resolve) => { release = resolve; }) };
  };
  const load = createModuleLoader();
  const identity = load(new URL('../api/identity.ts', import.meta.url));
  identity.setSessionIdentity(account('first'));
  const result = load(new URL('../api/client.ts', import.meta.url)).api.findings({ scan_id: 'historical',
    reassessment: '"not_reassessed","unknown"', sort_by: 'observed_at', sort_dir: 'desc', offset: 200 });
  await new Promise(setImmediate);
  const query = new URL(requested, 'https://node.example.test').searchParams;
  assert.equal(query.get('reassessment'), '"not_reassessed","unknown"');
  assert.equal(query.get('scan_id'), 'historical'); assert.equal(query.get('sort_by'), 'observed_at');
  assert.equal(query.get('sort_dir'), 'desc'); assert.equal(query.get('offset'), '200');
  identity.setSessionIdentity(account('second'));
  release(page({ total: 999, private: 'first-account' }));
  await assert.rejects(result, (error) => error.status === 0 && !error.message.includes('first-account'));
});
