import assert from 'node:assert/strict';
import test from 'node:test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import * as Mantine from '@mantine/core';
import { createModuleLoader } from '../lib/moduleTestSupport.mjs';
import { mount, target, ui } from '../lib/setupTestSupport.mjs';
import { permissionFixture } from './permissionTestSupport.mjs';

const h = React.createElement;
const load = createModuleLoader();
const core = { ...Mantine, Drawer: ({ opened, title, children }) => opened ? h('section', { role: 'dialog' }, title, children) : null };
const gate = load(new URL('./PermissionGate.tsx', import.meta.url), { '@mantine/core': core });
const component = load(new URL('./VsphereInventory.tsx', import.meta.url), { '@mantine/core': core });
const source = target({ id: 'vc-a', name: 'Inventory A', environment: 'alpha', authorization_id: 'gen-a',
  transport: 'vsphere', in_scope: true, options: { hypervisor: 'vsphere' } });
const render = (Component, props, actions = ['read', 'discover']) => renderToStaticMarkup(h(Mantine.MantineProvider, {},
  h(gate.PermissionProvider, { can: action => actions.includes(action) }, h(Component, props))));
const button = (html, name) => {
  const found = [...html.matchAll(/<button\b[^>]*>[\s\S]*?<\/button>/g)].map(m => m[0]).find(b => b.includes(`>${name}<`));
  assert.ok(found, `Missing button ${name}`); return found;
};
const snapshot = extra => ({ id: 'fixture', target_id: 'vc-a', source: 'vsphere', status: 'finished', complete: true,
  collection_started: true, observation_count: 0, observations: [], error: null,
  started_at: '2026-11-05T12:00:00Z', finished_at: '2026-11-05T12:01:00Z', ...extra });
const observation = (id, name, kind, state, ips = []) => ({ id, hostname: name, address: null,
  facts: { vsphere_kind: kind, vsphere_ref: id, power_state: state, reported_addresses: ips },
  evidence: [`Fixture inventory evidence for ${id}`], notes: 'Guest reachability untested' });

test('real read-only controls disable collection with keyboard-accessible permission explanations', () => {
  const html = render(component.VsphereInventory, { target: source, onClose() {} }, ['read']);
  const collect = button(html, 'Collect inventory');
  assert.match(collect, /\sdisabled(?:=|\s|>)/);
  assert.match(collect, /aria-describedby="[^"]+"/);
  const ids = /aria-describedby="([^"]+)"/.exec(collect)[1].split(' ');
  assert.ok(ids.some(id => html.includes(`id="${id}"`)));
  assert.match(html, /discover permission required/);
  assert.match(html, /role="group" tabindex="0" aria-disabled="true"/);
  assert.doesNotMatch(button(html, 'Refresh source history'), /\sdisabled(?:=|\s|>)/);
  assert.doesNotMatch(button(html, 'Close'), /\sdisabled(?:=|\s|>)/);
  assert.match(html, /Your source collections/);
  assert.doesNotMatch(html, /No saved collections|Complete empty inventory/);
});

test('rendering a permitted drawer never invokes collection or source history during SSR', () => {
  const html = render(component.VsphereInventory, { target: source, onClose() {} });
  assert.doesNotMatch(button(html, 'Collect inventory'), /\sdisabled(?:=|\s|>)/);
  const blocked = render(component.VsphereInventory, { target: source, blocked: 'Kill switch engaged', onClose() {} });
  assert.match(button(blocked, 'Collect inventory'), /\sdisabled(?:=|\s|>)/);
  assert.match(blocked, /Kill switch engaged/);
  const denied = render(component.VsphereInventory, { target: source, onClose() {} }, []);
  assert.match(denied, /read permission required/); assert.doesNotMatch(denied, /Collect inventory/);
});

test('VM and ESXi observations show reported data, retain offline/missing-IP inventory and escape metadata', () => {
  const rows = [observation('vm-1', '<script>inventory</script>', 'VirtualMachine', 'poweredOff', ['10.20.0.20']),
    observation('vm-2', 'Addressless VM', 'VirtualMachine', 'unknown'),
    observation('host-1', 'Hypervisor', 'HostSystem', 'poweredOn', ['10.20.0.2', '2001:db8::2'])];
  const html = render(component.VsphereSnapshot, { run: snapshot({ observations: rows, observation_count: 3 }) });
  assert.match(html, /vSphere inventory observations/);
  for (const expected of ['Name', 'Type', 'Reported IP', 'Power state', 'Evidence', 'ESXi host', 'VM',
    'poweredOff', 'Not reported', '10.20.0.20', '2001:db8::2', 'Fixture inventory evidence for vm-1', 'UTC']) assert.ok(html.includes(expected), expected);
  assert.match(html, /&lt;script&gt;inventory&lt;\/script&gt;/);
  assert.doesNotMatch(html, /<script>|>Online<|>Reachable</);
  assert.match(html, /Previous page/); assert.match(html, /Next page/);
  assert.doesNotMatch(html, />Accept<|>Register<|>Scan<|>Collect inventory</);
});

for (const status of ['failed', 'stopped', 'running', 'finished']) test(`incomplete ${status} never renders partial observations as an empty or complete snapshot`, () => {
  const html = render(component.VsphereSnapshot, { run: snapshot({ status, complete: false,
    error: 'vsphere:page_limit', observations: [observation('hidden', 'Partial private VM', 'VirtualMachine', 'poweredOn')] }) });
  assert.match(html, /Inventory snapshot incomplete/); assert.match(html, /vsphere:page_limit/);
  assert.match(html, /not evidence of an empty inventory/);
  assert.doesNotMatch(html, /Partial private VM|vSphere inventory observations|Complete empty inventory/);
});

test('complete empty inventory and a failure before collection have distinct rendered explanations', () => {
  const complete = render(component.VsphereSnapshot, { run: snapshot() });
  assert.match(complete, /Complete empty inventory/); assert.doesNotMatch(complete, /Inventory snapshot incomplete/);
  const local = render(component.VsphereSnapshot, { run: snapshot({ status: 'failed', complete: false,
    collection_started: false, error: 'vsphere:credential_unavailable' }) });
  assert.match(local, /collector was not invoked/); assert.doesNotMatch(local, /Complete empty inventory/);
});

test('only vSphere targets use the source inventory action, including legacy explicitly declared sources', () => {
  assert.equal(component.isVsphereTarget(source), true);
  assert.equal(component.isVsphereTarget(target({ options: { hypervisor: 'vsphere' } })), true);
  assert.equal(component.isVsphereTarget(target({ options: { hypervisor: 'vmware' } })), false);
  assert.equal(component.isVsphereTarget(target()), false);
});

test('Assets shows the source action on vSphere and retains the normal facts action on other assets', () => {
  const evaluate = createModuleLoader(), nothing = () => null;
  const permissions = evaluate(new URL('./PermissionGate.tsx', import.meta.url), { '@mantine/core': core });
  const vsphere = evaluate(new URL('./VsphereInventory.tsx', import.meta.url), { '@mantine/core': core });
  let n = 0;
  const common = { AsyncView: ({ state, children }) => children(state.data), AssetIcon: nothing, SimulatedBadge: nothing,
    SeverityBadge: nothing, Empty: nothing, PageTitle: ({ title, right }) => h('header', {}, title, right), Mono: ({ children }) => h('code', {}, children) };
  const { default: Assets } = evaluate(new URL('../pages/Assets.tsx', import.meta.url), {
    '@mantine/core': core,
    '../lib/format': { fmtAgo: () => 'Earlier' },
    '../lib/hooks': { useAsync: () => ({ data: n++ % 2 === 0 ? [source, target()] : [], loading: false, reload: async () => {} }) },
    '../components/PermissionGate': permissions, '../components/VsphereInventory': vsphere, '../components/common': common,
    '../components/setupAccess': { useSetupAccess: () => null }, '../components/TargetForm': { TargetForm: nothing },
    '../components/HostSetup': { HostSetup: nothing }, '../components/DiscoveryPanel': { DiscoveryPanel: nothing },
  });
  const html = renderToStaticMarkup(h(Mantine.MantineProvider, {}, h(permissions.PermissionProvider, { can: action => action === 'read' }, h(Assets))));
  assert.equal(html.split('View vSphere inventory').length - 1, 1);
  assert.equal(html.split('Read asset facts').length - 1, 1);
  assert.doesNotMatch(button(html, 'View vSphere inventory'), /\sdisabled(?:=|\s|>)/);
  assert.match(button(html, 'Read asset facts'), /\sdisabled(?:=|\s|>)/);
});

test('Assets source opener rechecks read and account authority before updating the drawer', async t => {
  const evaluate = createModuleLoader(), permissions = permissionFixture(['read']), rows = [source];
  const identity = evaluate(new URL('../api/identity.ts', import.meta.url));
  const account = { mode: 'oidc', authenticated: true, permissions: ['read'], principal: { actor: 'a', subject: 'a', roles: ['viewer'] } };
  identity.setSessionIdentity(account);
  let n = 0;
  const panel = mount(hooks => evaluate(new URL('../pages/Assets.tsx', import.meta.url), {
    '../lib/format': { fmtAgo: () => 'Earlier' },
    react: hooks, '@mantine/core': ui, '@tabler/icons-react': ui,
    '../api/client': { api: new Proxy({}, { get: () => () => assert.fail('Opening cannot make a remote facts call') }) },
    '../components/VsphereInventory': { VsphereInventory: 'VsphereInventory', isVsphereTarget: component.isVsphereTarget },
    '../components/PermissionGate': permissions.imports, '../components/setupAccess': { useSetupAccess: () => null },
    '../components/common': ui, '../components/TargetForm': ui, '../components/HostSetup': ui, '../components/DiscoveryPanel': ui,
    '../lib/hooks': { useAsync: () => ({ data: n++ % 2 === 0 ? rows : [], loading: false }) },
  }).default);
  t.after(() => panel.unmount()); await panel.settle();
  const nodes = value => Array.isArray(value) ? value.flatMap(nodes) : value && typeof value === 'object' ? [value, ...nodes(value.props?.children)] : [];
  const open = () => nodes(panel.find(n => n.type === 'AsyncView').props.children(rows)).find(n => n.props?.children === 'View vSphere inventory').props.onClick;
  const retained = open();
  permissions.state.actions = []; retained(); await panel.settle();
  assert.equal(panel.find(n => n.type === 'VsphereInventory').props.target, null);
  permissions.state.actions = ['read'];
  identity.setSessionIdentity({ ...account, principal: { ...account.principal, actor: 'b', subject: 'b' } });
  retained(); await panel.settle();
  assert.equal(panel.find(n => n.type === 'VsphereInventory').props.target, null);
  await panel.rerender(); open()(); await panel.settle();
  assert.equal(panel.find(n => n.type === 'VsphereInventory').props.target, source);
});
