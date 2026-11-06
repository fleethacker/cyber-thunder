import assert from 'node:assert/strict';
import test from 'node:test';
import { permissionFixture } from './permissionTestSupport.mjs';
import { actorProblem, errorText, evaluate, mount, target, types, ui } from '../lib/setupTestSupport.mjs';

async function setup(t, simulated = false) {
  const calls = [], ctx = { actor: 'IT1 Operator', status: { kill: { engaged: false } } };
  const permissions = permissionFixture();
  const asset = { id: 'candidate-id', hostname: 'candidate', address: '10.20.30.40', asset_type_guess: 'linux', facts: { simulated } };
  const api = new Proxy({ acceptAsset: (id, body) => new Promise((resolve, reject) => calls.push({ id, body, resolve, reject })) }, {
    get(object, name) { assert.ok(name in object, `Unexpected operation ${String(name)}`); return object[name]; },
  });
  let accepted = 0;
  const panel = mount((hooks) => evaluate(new URL('./DiscoveryPanel.tsx', import.meta.url), {
    react: hooks, '@mantine/core': ui, '@tabler/icons-react': ui, '@mantine/notifications': { notifications: { show() {} } },
    '../api/client': { api, errorText }, '../api/types': types, '../lib/format': {}, '../lib/hooks': {},
    './ConfirmReasonModal': ui, './ScopeEditor': ui, './common': ui,
    './PermissionGate': permissions.imports,
    './setupAccess': evaluate(new URL('./setupAccess.ts', import.meta.url), { '../state/AppState': { useAppState: () => ctx }, './ActorChip': { actorProblem } }),
  }).AcceptModal, { asset, onClose() {}, onAccepted: () => accepted++ });
  t.after(() => panel.unmount()); await panel.settle();
  return { ...panel, calls, ctx, permissions: permissions.state, accepted: () => accepted };
}

for (const choice of ['in', 'out']) {
  test(`discovery acceptance requires a fresh ${choice} choice and reason, without an automatic scan`, async (t) => {
    const panel = await setup(t);
    assert.equal(panel.control('Inventory authorization').props.value, '');
    panel.button('Accept').props.onClick(); assert.equal(panel.calls.length, 0);
    await panel.change('Inventory authorization', choice); await panel.change('Reason', 'Owner reviewed this candidate');
    await panel.click('Accept');
    assert.equal(panel.calls.length, 1); assert.equal(panel.calls[0].body.in_scope, choice === 'in');
    panel.calls[0].resolve(target({ in_scope: choice === 'in' })); await panel.settle();
    assert.equal(panel.accepted(), 1);
  });
}

test('discovery acceptance retains simulation and rechecks kill before duplicate-safe submission', async (t) => {
  const panel = await setup(t, true);
  assert.deepEqual(panel.control('Transport').props.data, ['simulated']);
  await panel.change('Inventory authorization', 'in'); await panel.change('Reason', 'Simulated candidate');
  panel.ctx.status.kill.engaged = true; await panel.rerender(); panel.button('Accept').props.onClick(); assert.equal(panel.calls.length, 0);
  panel.ctx.status.kill.engaged = false; await panel.rerender();
  const click = panel.button('Accept').props.onClick; click(); click(); await panel.settle();
  assert.equal(panel.calls.length, 1); assert.equal(panel.calls[0].body.transport, 'simulated');
});

test('discovery acceptance rechecks administration permission on a retained handler', async (t) => {
  const panel = await setup(t);
  await panel.change('Inventory authorization', 'in'); await panel.change('Reason', 'Owner reviewed candidate');
  const submit = panel.button('Accept').props.onClick;
  panel.permissions.actions = ['discover'];
  submit(); await panel.settle();
  assert.equal(panel.calls.length, 0);
  assert.equal(panel.accepted(), 0);
});

async function discovery(t) {
  const calls = [], permissions = permissionFixture(['discover', 'admin']);
  const candidate = { id: 'candidate', status: 'new' };
  const readings = [
    { data: { scopes: [], counts: { new: 1 }, last_run: null } },
    { data: [candidate] }, { data: [] },
  ].map(value => ({ ...value, loading: false, error: null, reload: async () => {} }));
  let readIndex = 0;
  const panel = mount(hooks => evaluate(new URL('./DiscoveryPanel.tsx', import.meta.url), {
    react: hooks, '@mantine/core': ui, '@tabler/icons-react': ui, '@mantine/notifications': { notifications: { show() {} } },
    '../api/client': { errorText, api: {
      sweep: async (...args) => { calls.push(['sweep', ...args]); return { id: 'run', status: 'finished' }; },
      ignoreAsset: async (...args) => { calls.push(['ignore', ...args]); },
    } }, '../api/types': types, '../lib/format': {},
    '../lib/hooks': { useAsync: () => readings[readIndex++ % 3], useInterval() {} },
    './PermissionGate': permissions.imports, './ScopeEditor': ui, './common': ui,
    './setupAccess': { useSetupAccess: () => null },
  }).DiscoveryPanel);
  t.after(() => panel.unmount()); await panel.settle();
  return { ...panel, calls, permissions: permissions.state };
}

test('a retained discovery handler cannot sweep after its permission is revoked', async (t) => {
  const panel = await discovery(t);
  const sweep = panel.button('Run sweep').props.onClick;
  panel.permissions.actions = ['read'];
  sweep(); await panel.settle();
  assert.equal(panel.calls.length, 0);
  panel.permissions.actions = ['discover'];
  await panel.click('Run sweep');
  assert.equal(panel.calls[0][0], 'sweep');
});

test('discovery-only users cannot open scope or candidate administration', async (t) => {
  const panel = await discovery(t);
  const row = panel.find(n => n.props?.a?.id === 'candidate');
  const edit = panel.button('Edit search ranges').props.onClick;
  panel.permissions.actions = ['discover'];
  row.props.onAccept(); row.props.onIgnore(); edit(); await panel.settle();
  assert.equal(panel.find(n => n.type === 'ScopeEditor').props.opened, false);
  assert.equal(panel.find(n => n.type === 'ConfirmReasonModal').props.opened, false);
  assert.equal(panel.find(n => n.props?.onAccepted).props.asset, null);
  assert.equal(panel.calls.length, 0);
});

test('an open ignore confirmation rechecks administration before submission', async (t) => {
  const panel = await discovery(t);
  panel.find(n => n.props?.a?.id === 'candidate').props.onIgnore(); await panel.settle();
  const modal = panel.find(n => n.type === 'ConfirmReasonModal');
  assert.equal(modal.props.opened, true);
  panel.permissions.actions = ['discover'];
  modal.props.onConfirm('Reviewed'); await panel.settle();
  assert.equal(panel.calls.length, 0);
});
