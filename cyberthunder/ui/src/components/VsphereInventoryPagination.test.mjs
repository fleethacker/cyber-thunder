import assert from 'node:assert/strict';
import test from 'node:test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import * as Mantine from '@mantine/core';
import { createModuleLoader } from '../lib/moduleTestSupport.mjs';
import { mount } from '../lib/setupTestSupport.mjs';

const h = React.createElement;
const observations = (count = 130) => Array.from({ length: count }, (_, index) => ({
  id: `object-${index}`, hostname: `Inventory-${String(index).padStart(3, '0')}`, address: null,
  facts: { vsphere_ref: `ref-${index}`, vsphere_kind: index % 2 ? 'HostSystem' : 'VirtualMachine',
    power_state: index % 3 ? 'poweredOn' : 'poweredOff', reported_addresses: [`10.20.0.${index + 1}`] },
  evidence: [`EVIDENCE-ONLY-FOR-${String(index).padStart(3, '0')}`], notes: `NOTES-ONLY-FOR-${String(index).padStart(3, '0')}`,
}));

async function setup(t, rows = observations()) {
  const load = createModuleLoader();
  const panel = mount(hooks => load(new URL('./VsphereInventory.tsx', import.meta.url), {
    react: hooks, '@mantine/core': Mantine,
  }).VsphereObservations, { observations: rows });
  t.after(() => panel.unmount()); await panel.settle();
  const root = () => panel.find(n => n.type === Mantine.Stack);
  return { ...panel,
    html: () => renderToStaticMarkup(h(Mantine.MantineProvider, {}, root())),
    async click(label) {
      const control = panel.find(n => n.type === Mantine.Button && n.props.children === label);
      assert.ok(!control.props.disabled, `${label} disabled`); control.props.onClick(); await panel.settle();
    },
  };
}

function rowNames(html) {
  const tbody = /<tbody\b[^>]*>([\s\S]*?)<\/tbody>/.exec(html)?.[1] ?? '';
  return [...tbody.matchAll(/Inventory-\d{3}/g)].map(m => m[0]);
}

test('the actual default table renders only 25 rows and their evidence, with snapshot and matching counts', async t => {
  const panel = await setup(t), html = panel.html();
  assert.deepEqual(rowNames(html), observations().slice(0, 25).map(row => row.hostname));
  assert.match(html, /Showing 1–25 of 130 matching observations/);
  assert.match(html, /130 observations in this complete saved snapshot/);
  assert.match(html, /do not describe the entire vCenter inventory/);
  assert.match(html, /EVIDENCE-ONLY-FOR-024/);
  assert.doesNotMatch(html, /Inventory-025|EVIDENCE-ONLY-FOR-025|NOTES-ONLY-FOR-129/);
});

test('next and previous pages preserve snapshot order and remove prior-page metadata from the DOM', async t => {
  const panel = await setup(t);
  await panel.click('Next page'); let html = panel.html();
  assert.deepEqual(rowNames(html), observations().slice(25, 50).map(row => row.hostname));
  assert.match(html, /Showing 26–50 of 130/);
  assert.doesNotMatch(html, /EVIDENCE-ONLY-FOR-000|NOTES-ONLY-FOR-000/);
  await panel.click('Previous page'); html = panel.html();
  assert.deepEqual(rowNames(html), observations().slice(0, 25).map(row => row.hostname));
  assert.doesNotMatch(html, /EVIDENCE-ONLY-FOR-049/);
});

test('25, 50 and 100 are the only page sizes, reset to page one, and never render more than 100 rows', async t => {
  const panel = await setup(t);
  await panel.click('Next page');
  await panel.change('Observations per page', '50');
  assert.equal(rowNames(panel.html()).length, 50); assert.match(panel.html(), /Showing 1–50/);
  await panel.change('Observations per page', '100');
  assert.equal(rowNames(panel.html()).length, 100);
  assert.doesNotMatch(panel.html(), /EVIDENCE-ONLY-FOR-100/);
  await panel.click('Next page');
  assert.equal(rowNames(panel.html()).length, 30); assert.match(panel.html(), /Showing 101–130/);
  await panel.change('Observations per page', '5000');
  assert.equal(rowNames(panel.html()).length, 30);
  await panel.change('Observations per page', '25');
  assert.equal(rowNames(panel.html()).length, 25); assert.match(panel.html(), /Showing 1–25/);
});

test('combined type and power filters count only matching rows and reveal no excluded evidence or notes', async t => {
  const panel = await setup(t);
  await panel.click('Next page');
  await panel.change('Inventory type', 'HostSystem');
  await panel.change('Reported power state', 'poweredOff');
  const expected = observations().filter((_, index) => index % 2 && index % 3 === 0);
  const html = panel.html();
  assert.deepEqual(rowNames(html), expected.map(row => row.hostname));
  assert.match(html, /Showing 1–22 of 22 matching observations/);
  assert.match(html, /130 observations in this complete saved snapshot/);
  assert.doesNotMatch(html, /Inventory-000|EVIDENCE-ONLY-FOR-000|NOTES-ONLY-FOR-001/);
  await panel.click('Reset filters');
  assert.deepEqual(rowNames(panel.html()), observations().slice(0, 25).map(row => row.hostname));
});

test('search is local to names, object references and IPs, resets pages and does not summarize hidden metadata', async t => {
  const rows = observations(); rows[112].hostname = 'École 東京';
  const panel = await setup(t, rows);
  await panel.click('Next page');
  for (const query of ['ÉCOLE', 'ref-112', '10.20.0.113']) {
    await panel.change('Search name, object ID or reported IP', query);
    const html = panel.html();
    assert.match(html, /École 東京/); assert.match(html, /Showing 1–1 of 1/);
    assert.match(html, /EVIDENCE-ONLY-FOR-112/);
    assert.doesNotMatch(html, /EVIDENCE-ONLY-FOR-000|NOTES-ONLY-FOR-111/);
  }
  await panel.change('Search name, object ID or reported IP', 'EVIDENCE-ONLY-FOR');
  const html = panel.html();
  assert.match(html, /No observations match these filters/);
  assert.match(html, /saved snapshot contains 130 observations/);
  assert.doesNotMatch(html, /<tbody|NOTES-ONLY-FOR|Complete empty inventory/);
});

test('unknown type and power filters include missing data without including other rows', async t => {
  const rows = observations(2); rows[1].facts = { vsphere_ref: 'missing', reported_addresses: [] };
  const panel = await setup(t, rows);
  await panel.change('Inventory type', 'unknown'); await panel.change('Reported power state', 'unknown');
  const html = panel.html();
  assert.deepEqual(rowNames(html), ['Inventory-001']); assert.match(html, /Not reported/);
  assert.doesNotMatch(html, /EVIDENCE-ONLY-FOR-000/);
});

test('the observation subtree key changes with run, target ownership and current account authority', () => {
  const load = createModuleLoader();
  const identity = load(new URL('../api/identity.ts', import.meta.url));
  const { VsphereSnapshot, VsphereObservations } = load(new URL('./VsphereInventory.tsx', import.meta.url), { '@mantine/core': Mantine });
  const run = { id: 'first', target_id: 'source', authorization_scope: { authorization_id: 'generation-one' },
    status: 'finished', complete: true, observations: observations(1), started_at: '2026-11-05T00:00:00Z', finished_at: null };
  const key = value => {
    const children = React.Children.toArray(VsphereSnapshot({ run: value }).props.children);
    return children.find(child => child.type === VsphereObservations).key;
  };
  const first = key(run);
  assert.notEqual(key({ ...run, id: 'second' }), first);
  assert.notEqual(key({ ...run, authorization_scope: { authorization_id: 'generation-two' } }), first);
  identity.setSessionIdentity({ mode: 'oidc', authenticated: true, permissions: ['read'],
    principal: { actor: 'another-account', subject: 'another', roles: ['viewer'] } });
  assert.notEqual(key(run), first);
});
