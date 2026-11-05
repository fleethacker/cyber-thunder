import assert from 'node:assert/strict';
import test from 'node:test';
import { actorProblem, errorText, evaluate, mount, target, types, ui } from '../lib/setupTestSupport.mjs';

const context = () => ({ actor: 'IT1 Operator', status: { kill: { engaged: false } }, statusError: null });
const access = (ctx) => evaluate(new URL('./setupAccess.ts', import.meta.url), {
  '../state/AppState': { useAppState: () => ctx }, './ActorChip': { actorProblem },
});

async function setup(t, initial = null, defaults) {
  const ctx = context(), calls = [];
  let saved = 0, closed = 0;
  const props = { opened: true, initial, defaults, onSaved: () => saved++, onClose: () => closed++ };
  const api = new Proxy({
    addTarget: (body) => new Promise((resolve, reject) => calls.push({ kind: 'add', body, resolve, reject })),
    updateTarget: (id, body) => new Promise((resolve, reject) => calls.push({ kind: 'update', id, body, resolve, reject })),
  }, { get(object, name) { assert.ok(name in object, `Unexpected operation: ${String(name)}`); return object[name]; } });
  const panel = mount((hooks) => evaluate(new URL('./TargetForm.tsx', import.meta.url), {
    react: hooks, '@mantine/core': ui, '../api/client': { api, errorText }, '../api/types': types,
    './setupAccess': access(ctx),
  }).TargetForm, props);
  t.after(() => panel.unmount());
  await panel.settle();
  return { ...panel, calls, ctx, saved: () => saved, closed: () => closed,
    async update(next) { Object.assign(props, next); await panel.rerender(props); },
  };
}

test('new registration has no scope default and requires a reason and a separate review/confirmation', async (t) => {
  const panel = await setup(t);
  assert.equal(panel.control('Inventory authorization').props.value, '');
  assert.equal(panel.calls.length, 0);
  await panel.change('ID', 'host-alias');
  await panel.submit();
  assert.equal(panel.button('Review registration').props.disabled, true);
  await panel.change('Inventory authorization', 'out');
  await panel.change('Authorization reason', '   ');
  await panel.submit();
  assert.equal(panel.calls.length, 0);
  await panel.change('Authorization reason', 'Owner has not authorized scanning');
  await panel.submit();
  assert.equal(panel.calls.length, 0, 'Review must not create, probe or scan');
  assert.ok(panel.button('Confirm registration'));
  await panel.submit();
  assert.equal(panel.calls.length, 1);
  assert.equal(panel.calls[0].body.in_scope, false);
  assert.match(panel.calls[0].body.notes, /Owner has not authorized scanning/);
  panel.calls[0].resolve(target({ id: 'host-alias' })); await panel.settle();
  assert.equal(panel.saved(), 1); assert.equal(panel.closed(), 1);
});

test('authorization is a deliberate single-target choice, never an implicit scan', async (t) => {
  const panel = await setup(t);
  await panel.change('ID', 'explicit-host');
  await panel.change('Inventory authorization', 'in');
  await panel.change('Authorization reason', 'Approved by the asset owner');
  await panel.submit(); await panel.submit();
  assert.equal(panel.calls.length, 1);
  assert.equal(panel.calls[0].body.in_scope, true);
  assert.equal(panel.calls[0].kind, 'add');
});

test('reviewed registration rechecks actor and kill before writing, then prevents duplicate submission', async (t) => {
  const panel = await setup(t);
  await panel.change('ID', 'host'); await panel.change('Inventory authorization', 'out');
  await panel.change('Authorization reason', 'Awaiting owner'); await panel.submit();
  for (const update of [{ actor: '' }, { actor: 'IT1 Operator', status: { kill: { engaged: true } } },
    { status: null }, { status: { kill: { engaged: false } }, statusError: 'Refresh failed' }]) {
    Object.assign(panel.ctx, update); await panel.rerender();
    assert.equal(panel.button('Confirm registration').props.disabled, true);
    await panel.submit(); assert.equal(panel.calls.length, 0);
  }
  Object.assign(panel.ctx, context()); await panel.rerender();
  const handler = panel.find((node) => node.type === 'form').props.onSubmit;
  handler({ preventDefault() {} }); handler({ preventDefault() {} }); await panel.settle();
  assert.equal(panel.calls.length, 1);
  panel.find((node) => node.type === 'Modal').props.onClose();
  assert.equal(panel.closed(), 0);
  panel.calls[0].reject(new Error('Registration refused')); await panel.settle();
  assert.equal(panel.saved(), 0);
  assert.ok(panel.nodes().some((node) => node.props?.children === 'Registration refused'));
});

test('editing preserves aliases, scope and unknown connection options without reauthorizing', async (t) => {
  const original = target();
  const panel = await setup(t, original);
  assert.equal(panel.control('ID').props.disabled, true);
  await panel.change('Name', 'Updated display alias');
  await panel.submit();
  assert.equal(panel.calls[0].kind, 'update');
  assert.equal(panel.calls[0].id, original.id);
  assert.equal(panel.calls[0].body.name, 'Updated display alias');
  assert.equal('in_scope' in panel.calls[0].body, false);
  assert.deepEqual(panel.calls[0].body.options, original.options);
  assert.equal(panel.calls[0].body.credential_ref, original.credential_ref);
});

test('local transport warning distinguishes the service container from its physical host', async (t) => {
  const panel = await setup(t);
  await panel.change('Transport', 'local');
  assert.ok(panel.nodes().some((node) => typeof node.props?.children === 'string' && node.props.children.includes('local means that container, not its physical host')));
  assert.equal(panel.calls.length, 0);
});

test('reopening registration clears the previous authorization and review', async (t) => {
  const panel = await setup(t);
  await panel.change('ID', 'first'); await panel.change('Inventory authorization', 'in');
  await panel.change('Authorization reason', 'First host only'); await panel.submit();
  await panel.update({ opened: false }); await panel.update({ opened: true });
  assert.equal(panel.control('Inventory authorization').props.value, '');
  assert.equal(panel.control('Authorization reason').props.value, '');
  assert.equal(panel.button('Review registration').props.disabled, true);
});

test('native local defaults still require explicit scope and review without authorizing from a preset', async (t) => {
  const panel = await setup(t, null, { asset_type: 'windows', transport: 'local', sudo: false, in_scope: true });
  assert.equal(panel.control('Transport').props.value, 'local');
  assert.equal(panel.control('Asset type').props.value, 'windows');
  assert.equal(panel.control('Inventory authorization').props.value, '');
  assert.equal(panel.calls.length, 0);
  await panel.change('ID', 'native-alias'); await panel.change('Inventory authorization', 'out');
  await panel.change('Authorization reason', 'Record local environment only'); await panel.submit(); await panel.submit();
  assert.equal(panel.calls[0].body.in_scope, false);
  assert.equal(panel.calls[0].body.transport, 'local');
});

test('setup action guard rejects missing/machine actors and unknown or engaged kill state', () => {
  const { setupActionProblem } = access(context());
  for (const actor of ['', 'system', 'agent', 'llm', 'agent:worker', 'system:service', 'policy:auto']) {
    assert.ok(setupActionProblem({ ...context(), actor }), actor);
  }
  assert.ok(setupActionProblem({ ...context(), status: null }));
  assert.ok(setupActionProblem({ ...context(), status: { kill: { engaged: true } } }));
  assert.ok(setupActionProblem({ ...context(), statusError: 'unavailable' }));
  assert.equal(setupActionProblem(context()), null);
});
