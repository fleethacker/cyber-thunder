import assert from 'node:assert/strict';
import test from 'node:test';
import { actorProblem, errorText, evaluate, mount, target, types, ui } from '../lib/setupTestSupport.mjs';

async function setup(t, simulated = false) {
  const calls = [], ctx = { actor: 'IT1 Operator', status: { kill: { engaged: false } } };
  const asset = { id: 'candidate-id', hostname: 'candidate', address: '10.20.30.40', asset_type_guess: 'linux', facts: { simulated } };
  const api = new Proxy({ acceptAsset: (id, body) => new Promise((resolve, reject) => calls.push({ id, body, resolve, reject })) }, {
    get(object, name) { assert.ok(name in object, `Unexpected operation ${String(name)}`); return object[name]; },
  });
  let accepted = 0;
  const panel = mount((hooks) => evaluate(new URL('./DiscoveryPanel.tsx', import.meta.url), {
    react: hooks, '@mantine/core': ui, '@tabler/icons-react': ui, '@mantine/notifications': { notifications: { show() {} } },
    '../api/client': { api, errorText }, '../api/types': types, '../lib/format': {}, '../lib/hooks': {},
    './ConfirmReasonModal': ui, './ScopeEditor': ui, './common': ui,
    './setupAccess': evaluate(new URL('./setupAccess.ts', import.meta.url), { '../state/AppState': { useAppState: () => ctx }, './ActorChip': { actorProblem } }),
  }).AcceptModal, { asset, onClose() {}, onAccepted: () => accepted++ });
  t.after(() => panel.unmount()); await panel.settle();
  return { ...panel, calls, ctx, accepted: () => accepted };
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
