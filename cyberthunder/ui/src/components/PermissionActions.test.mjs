import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluate, mount, ui } from '../lib/setupTestSupport.mjs';
import { permissionFixture } from './permissionTestSupport.mjs';

async function policy(t, actions) {
  const permissions = permissionFixture(actions), calls = [];
  let queueRead;
  const api = {
    async policy() { return { version: 1, enabled: false, rules: [] }; },
    async putPolicy(body) { calls.push(['put', body]); throw new Error('Policy change refused by server'); },
    proposals() { calls.push(['queue']); return new Promise((resolve) => { queueRead = resolve; }); },
    async evaluatePolicy(id) { calls.push(['evaluate', id]); return { auto_eligible: false, reasons: ['Read-only evaluation'] }; },
  };
  const panel = mount((hooks) => evaluate(new URL('./PolicyEditor.tsx', import.meta.url), {
    react: hooks, '@mantine/core': ui, '@mantine/notifications': { notifications: { show() {} } },
    '../api/client': { api, errorText: (e) => e.message }, '../api/types': { ASSET_TYPES: ['linux'] },
    '../lib/format': { fmtTime: (v) => v }, './common': ui, './PermissionGate': permissions.imports,
    '../state/AppState': { useAppState: () => ({ actor: 'verified-fixture', refresh: async () => {} }) },
    '../lib/hooks': evaluate(new URL('../lib/hooks.ts', import.meta.url), { react: hooks, '../api/client': { errorText: (e) => e.message } }),
  }).PolicyEditor);
  t.after(() => panel.unmount()); await panel.settle();
  return { ...panel, calls, permissions: permissions.state,
    confirm: () => panel.find((node) => node.type === 'ConfirmReasonModal').props,
    async queue() { queueRead({ proposals: [{ id: 'proposal', title: 'Change', severity: 'low' }] }); await panel.settle(); },
  };
}

test('a read-only policy viewer cannot enable or save through retained handlers but can evaluate saved policy', async (t) => {
  const panel = await policy(t, ['read']);
  await panel.click('Add rule'); await panel.click('Save rules');
  panel.control('Off').props.onChange(); await panel.settle();
  assert.equal(panel.confirm().opened, false);
  panel.confirm().onConfirm('Attempted direct submit'); await panel.settle();
  assert.equal(panel.calls.length, 0);
  await panel.click('Evaluate against current queue'); await panel.queue();
  assert.deepEqual(panel.calls, [['queue'], ['evaluate', 'proposal']]);
});

test('permission loss closes the policy mutation path while the old confirmation callback is retained', async (t) => {
  const panel = await policy(t, ['policy', 'read']);
  await panel.click('Save rules'); assert.equal(panel.confirm().opened, true);
  const confirm = panel.confirm().onConfirm;
  panel.permissions.actions = ['read']; await panel.rerender();
  confirm('Previously available'); await panel.settle();
  assert.equal(panel.calls.length, 0);
  panel.permissions.actions = ['policy']; await panel.rerender();
  panel.confirm().onConfirm('Explicit change'); await panel.settle();
  assert.equal(panel.calls.length, 1);
  assert.equal(panel.confirm().opened, true);
  assert.equal(panel.confirm().error, 'Policy change refused by server');
});

test('saved-policy evaluation rechecks read access after its queue request before the next operation', async (t) => {
  const panel = await policy(t, ['read']);
  await panel.click('Evaluate against current queue');
  panel.permissions.actions = []; await panel.rerender();
  await panel.queue(); assert.deepEqual(panel.calls, [['queue']]);
});
