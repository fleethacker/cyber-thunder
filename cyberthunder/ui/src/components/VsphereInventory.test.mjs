import assert from 'node:assert/strict';
import test from 'node:test';
import { createModuleLoader } from '../lib/moduleTestSupport.mjs';
import { mount, target, ui } from '../lib/setupTestSupport.mjs';
import { permissionFixture } from './permissionTestSupport.mjs';

const source = (extra = {}) => target({ id: 'vc-a', name: 'Inventory A', transport: 'vsphere', environment: 'alpha',
  authorization_id: 'generation-a', in_scope: true, options: { hypervisor: 'vsphere' }, ...extra });
const who = (permissions = ['read', 'discover']) => ({ mode: 'oidc', authenticated: true, login_available: true,
  csrf_token: 'fixture-csrf', principal: { actor: 'human:alice', issuer: 'https://identity.test', subject: 'alice',
    name: 'Alice', roles: ['analyst'], source: 'oidc', verified: true }, permissions });
const run = (id = 'run-a', extra = {}, resource = source()) => ({ version: 1, id, source: 'vsphere', target_id: resource.id,
  authorization_scope: { version: 1, target_id: resource.id, environment: resource.environment, authorization_id: resource.authorization_id },
  requested_by: 'human:alice', requested_principal: { kind: 'human', iss: 'https://identity.test', sub: 'alice', name: 'Alice',
    roles: ['analyst'], via: 'oidc', verified: true }, started_at: '2026-11-05T12:00:00Z', finished_at: '2026-11-05T12:00:01Z',
  status: 'finished', collection_started: true, complete: true, observation_count: 0, error: null, observations: [], ...extra });
const brief = ({ observations, ...summary }) => summary;
const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };

async function setup(t, { actions = ['read', 'discover'], resource = source(), opened = true } = {}) {
  const previous = { fetch: globalThis.fetch, window: globalThis.window };
  globalThis.window = new EventTarget();
  const requests = [], permissions = permissionFixture(actions), load = createModuleLoader();
  const identity = load(new URL('../api/identity.ts', import.meta.url));
  identity.setSessionIdentity(who(actions));
  globalThis.fetch = (url, init) => {
    assert.match(url, /^\/api\/v1\/discovery\/vsphere\/[^/]+\/(collect|runs(?:\/[^/]+)?)(?:\?limit=20)?$/,
      'Only this explicitly selected source can be accessed');
    const pending = deferred();
    requests.push({ url, ...init, ...pending });
    return pending.promise;
  };
  let closed = 0;
  let props = { target: opened ? resource : null, blocked: null, onClose: () => closed++ };
  const panel = mount(hooks => load(new URL('./VsphereInventory.tsx', import.meta.url), {
    react: hooks, '@mantine/core': ui, './PermissionGate': permissions.imports,
  }).VsphereInventory, props);
  t.after(() => { panel.unmount(); Object.assign(globalThis, previous); });
  await panel.settle();
  const texts = () => JSON.stringify(panel.nodes().map(n => [n.type, n.props?.title, n.props?.children]),
    (_key, v) => typeof v === 'function' ? v.name : v);
  const selected = () => panel.nodes().find(n => n.type?.name === 'VsphereSnapshot')?.props.run ?? null;
  return { ...panel, requests, identity, permissions: permissions.state, selected, texts, closed: () => closed,
    async respond(value, index = requests.length - 1, status = 200) {
      requests[index].resolve(new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } }));
      await panel.settle();
    },
    async update(update) { props = { ...props, ...update }; await panel.rerender(props); },
    async changeAccount(next, render = true) {
      permissions.state.actions = next?.permissions ?? [];
      identity.setSessionIdentity(next);
      if (render) await panel.rerender(props);
    },
  };
}

test('opening reads only this source history, with no implicit collection, target acceptance or scan', async t => {
  const panel = await setup(t, { opened: false });
  assert.equal(panel.requests.length, 0);
  await panel.update({ target: source() });
  assert.deepEqual(panel.requests.map(r => [r.method, r.url]), [['GET', '/api/v1/discovery/vsphere/vc-a/runs?limit=20']]);
  await panel.respond([brief(run())]);
  assert.equal(panel.requests.length, 1, 'Loading history must not auto-read details or collect');
  assert.match(panel.texts(), /Your source collections/);
  assert.equal(panel.selected(), null);
  panel.control('View collection run-a').props.onClick(); await panel.settle();
  assert.equal(panel.requests[1].url, '/api/v1/discovery/vsphere/vc-a/runs/run-a');
  await panel.respond(run());
  assert.equal(panel.selected().id, 'run-a');
  assert.ok(panel.requests.every(r => r.method === 'GET'));
});

test('a read-only account can view saved runs, but retained collection handlers cannot POST', async t => {
  const panel = await setup(t, { actions: ['read'] });
  await panel.respond([brief(run())]);
  panel.button('Collect inventory').props.onClick(); await panel.settle();
  assert.equal(panel.requests.length, 1);
  panel.control('View collection run-a').props.onClick(); await panel.settle();
  await panel.respond(run());
  assert.equal(panel.selected().id, 'run-a');
  assert.equal(panel.requests.length, 2);
});

test('without read permission, mounting makes no requests and explains the restriction', async t => {
  const panel = await setup(t, { actions: ['discover'] });
  assert.equal(panel.requests.length, 0);
  assert.match(panel.texts(), /lacks read permission/);
  await panel.click('Close'); assert.equal(panel.closed(), 1);
});

test('collection is explicit, carries existing CSRF protection and suppresses duplicate pending handlers', async t => {
  const panel = await setup(t);
  await panel.respond([]);
  const submit = panel.button('Collect inventory').props.onClick;
  submit(); submit(); await panel.settle();
  assert.equal(panel.requests.length, 2);
  const request = panel.requests[1];
  assert.equal(request.method, 'POST'); assert.equal(request.url, '/api/v1/discovery/vsphere/vc-a/collect');
  assert.equal(request.headers['X-CSRF-Token'], 'fixture-csrf'); assert.equal(request.body, '{}');
  assert.equal(panel.button('Collect inventory').props.loading, true);
  assert.equal(panel.button('Refresh source history').props.disabled, true);
  assert.doesNotMatch(panel.texts(), /No saved collections/);
  await panel.respond(run('explicit'));
  assert.equal(panel.selected().id, 'explicit');
  assert.equal(panel.requests.length, 2, 'No automatic accept, scan or follow-up collection');
  assert.ok(panel.control('View collection explicit'));
  assert.equal(panel.button('Collect inventory').props.loading, false);
});

test('failed history is never presented as no saved collections and can be retried', async t => {
  const panel = await setup(t);
  await panel.respond({ detail: 'Source history unavailable on server' }, 0, 503);
  assert.match(panel.texts(), /Source history unavailable/);
  assert.doesNotMatch(panel.texts(), /No saved collections/);
  await panel.click('Refresh source history'); await panel.respond([]);
  assert.match(panel.texts(), /No saved collections for your account/);
  assert.doesNotMatch(panel.texts(), /Source history unavailable/);
});

test('a failed collection stays incomplete and history errors survive a successful POST', async t => {
  const panel = await setup(t);
  await panel.respond({ detail: 'History service unavailable' }, 0, 503);
  await panel.click('Collect inventory');
  await panel.respond(run('failed', { status: 'failed', complete: false, error: 'vsphere:credential_unavailable', collection_started: false }));
  assert.equal(panel.selected().complete, false);
  assert.equal(panel.selected().collection_started, false);
  assert.match(panel.texts(), /saved history is still unavailable/);
  assert.doesNotMatch(panel.texts(), /No saved collections/);
});

test('an HTTP collection failure reports unknown completion and never claims empty success', async t => {
  const panel = await setup(t); await panel.respond([]);
  await panel.click('Collect inventory');
  await panel.respond({ detail: 'vsphere:publication_failed' }, 1, 503);
  assert.equal(panel.selected(), null);
  assert.match(panel.texts(), /completion may be unknown/);
  assert.doesNotMatch(panel.texts(), /Complete empty inventory|No saved collections/);
});

for (const failure of ['detail', 'history', 'collect']) test(`${failure} refusal clears previously loaded source details`, async t => {
  const panel = await setup(t); await panel.respond([brief(run())]);
  panel.control('View collection run-a').props.onClick(); await panel.settle(); await panel.respond(run());
  assert.ok(panel.selected());
  if (failure === 'detail') panel.control('View collection run-a').props.onClick();
  else await panel.click(failure === 'history' ? 'Refresh source history' : 'Collect inventory');
  await panel.settle(); await panel.respond({ detail: 'Current account is not authorized' }, panel.requests.length - 1, 403);
  assert.equal(panel.selected(), null);
  assert.ok(!panel.nodes().some(n => n.props?.['aria-label'] === 'View collection run-a'));
  assert.match(panel.texts(), /not authorized/);
  assert.doesNotMatch(panel.texts(), /No saved collections/);
});

test('permission and kill/scope changes are checked again inside retained handlers', async t => {
  const panel = await setup(t); await panel.respond([]);
  const submit = panel.button('Collect inventory').props.onClick;
  panel.permissions.actions = ['read']; submit(); await panel.settle();
  assert.equal(panel.requests.length, 1);
  panel.permissions.actions = ['read', 'discover'];
  await panel.update({ blocked: 'Kill switch engaged' }); submit(); await panel.settle();
  assert.equal(panel.requests.length, 1);
  await panel.update({ blocked: null, target: source({ in_scope: false }) });
  assert.equal(panel.requests.length, 2); await panel.respond([]);
  panel.button('Collect inventory').props.onClick(); await panel.settle();
  assert.equal(panel.requests.length, 2);
});

for (const kind of ['history', 'detail', 'collect']) for (const error of [false, true]) {
  test(`late ${kind} ${error ? 'error' : 'result'} cannot cross accounts or release the new request lock`, async t => {
    const panel = await setup(t);
    if (kind !== 'history') {
      await panel.respond([brief(run())]);
      if (kind === 'detail') panel.control('View collection run-a').props.onClick();
      else await panel.click('Collect inventory');
      await panel.settle();
    }
    const previous = panel.requests.length - 1;
    const bob = who(); bob.principal = { ...bob.principal, actor: 'human:bob', subject: 'bob' }; bob.csrf_token = 'fixture-bob';
    await panel.changeAccount(bob);
    const latest = panel.requests.length - 1;
    assert.ok(latest > previous);
    await panel.respond(error ? { detail: 'Alice private failure' } : kind === 'history' ? [brief(run('alice-private'))] : run('alice-private'), previous, error ? 403 : 200);
    assert.doesNotMatch(panel.texts(), /Alice private failure|alice-private/);
    assert.equal(panel.selected(), null);
    assert.equal(panel.button('Refresh source history').props.disabled, true, 'Old finally must not unlock the new request');
    panel.button('Collect inventory').props.onClick(); await panel.settle(); assert.equal(panel.requests.length - 1, latest);
    await panel.respond([], latest);
    assert.equal(panel.button('Collect inventory').props.disabled, false);
  });
}

for (const operation of ['detail', 'collect']) test(`${operation} body decoding cannot publish after account authority changes`, async t => {
  const panel = await setup(t); await panel.respond([brief(run())]);
  if (operation === 'detail') panel.control('View collection run-a').props.onClick();
  else await panel.click('Collect inventory');
  await panel.settle();
  const body = deferred();
  panel.requests[1].resolve({ ok: true, headers: new Headers({ 'Content-Type': 'application/json' }), json: () => body.promise });
  await panel.settle();
  const changed = who(['read']);
  await panel.changeAccount(changed);
  body.reject(new SyntaxError('Old account private malformed body'));
  await panel.settle();
  assert.equal(panel.selected(), null); assert.doesNotMatch(panel.texts(), /private malformed body/);
  await panel.respond([], 2);
});

test('read revocation while a request is pending discards results and prevents additional reads', async t => {
  const panel = await setup(t);
  const reload = panel.button('Refresh source history').props.onClick;
  await panel.changeAccount(who([]));
  await panel.respond([brief(run('revoked-private'))], 0);
  reload(); await panel.settle();
  assert.equal(panel.requests.length, 1); assert.doesNotMatch(panel.texts(), /revoked-private/);
  assert.match(panel.texts(), /lacks read permission/);
});

test('retained collection handlers check current authority even before a React rerender', async t => {
  const panel = await setup(t); await panel.respond([]);
  const collect = panel.button('Collect inventory').props.onClick;
  const next = who(); next.principal = { ...next.principal, actor: 'human:bob', subject: 'bob' };
  await panel.changeAccount(next, false);
  collect(); await panel.settle(); assert.equal(panel.requests.length, 1);
  await panel.rerender(); await panel.respond([], 1);
  collect(); await panel.settle(); assert.equal(panel.requests.length, 2);
});

test('history stays bounded to twenty and explicit collection adds its returned run without extra requests', async t => {
  const panel = await setup(t);
  await panel.respond(Array.from({ length: 21 }, (_, i) => brief(run(`run-${i}`))));
  assert.equal(panel.nodes().filter(n => n.props?.['aria-label']?.startsWith('View collection ')).length, 20);
  assert.ok(!panel.nodes().some(n => n.props?.['aria-label'] === 'View collection run-20'));
  await panel.click('Collect inventory'); await panel.respond(run('newest'));
  const rows = panel.nodes().filter(n => n.props?.['aria-label']?.startsWith('View collection '));
  assert.equal(rows.length, 20); assert.equal(rows[0].props['aria-label'], 'View collection newest');
  assert.equal(panel.requests.length, 2);
});

test('an account change during error decoding cannot expose the prior response or expire the new account', async t => {
  const panel = await setup(t); await panel.respond([]); await panel.click('Collect inventory');
  const body = deferred();
  panel.requests[1].resolve({ ok: false, status: 401, statusText: 'Unauthorized', text: () => body.promise });
  await panel.settle();
  const next = who(); next.principal = { ...next.principal, actor: 'human:bob', subject: 'bob' };
  await panel.changeAccount(next);
  body.resolve(JSON.stringify({ detail: 'Old account private failure' })); await panel.settle();
  assert.equal(panel.identity.sessionIdentity(), next);
  assert.doesNotMatch(panel.texts(), /Old account private failure/);
  await panel.respond([], 2);
});

for (const field of ['id', 'authorization_id', 'address']) test(`a source ${field} change ignores the old pending collection`, async t => {
  const panel = await setup(t); await panel.respond([]); await panel.click('Collect inventory');
  const changed = source({ [field]: field === 'id' ? 'vc-b' : field === 'address' ? '10.20.30.99' : 'generation-new' });
  await panel.update({ target: changed });
  await panel.respond(run('old-generation'), 1);
  assert.equal(panel.selected(), null); assert.doesNotMatch(panel.texts(), /old-generation/);
  await panel.respond([], 2);
  assert.equal(panel.button('Collect inventory').props.disabled, false);
});

test('a response with a different target generation is refused even without a prop change', async t => {
  const panel = await setup(t);
  await panel.respond([brief(run('wrong', {}, source({ authorization_id: 'wrong-generation' })))]);
  assert.match(panel.texts(), /no longer matches this target/);
  assert.equal(panel.selected(), null);
  assert.ok(!panel.nodes().some(n => n.props?.['aria-label'] === 'View collection wrong'));
});

for (const kind of ['history', 'detail', 'collect']) test(`unmount while ${kind} is pending causes no late state writes`, async t => {
  const panel = await setup(t);
  if (kind !== 'history') {
    await panel.respond([brief(run())]);
    if (kind === 'detail') panel.control('View collection run-a').props.onClick();
    else await panel.click('Collect inventory');
    await panel.settle();
  }
  panel.unmount();
  await panel.respond(kind === 'history' ? [brief(run())] : run());
  assert.equal(panel.lateWrites(), 0);
});

test('closing a pending collection ignores it; reopening cannot be unlocked by the old completion', async t => {
  const panel = await setup(t); await panel.respond([]); await panel.click('Collect inventory');
  await panel.click('Close'); await panel.update({ target: null }); await panel.update({ target: source() });
  await panel.respond(run('closed'), 1);
  assert.equal(panel.selected(), null); assert.equal(panel.button('Refresh source history').props.disabled, true);
  await panel.respond([], 2); assert.doesNotMatch(panel.texts(), /View collection closed/);
});

test('source API identifiers are encoded and history is explicitly bounded to twenty', async t => {
  const previous = globalThis.fetch, requests = [];
  t.after(() => { globalThis.fetch = previous; });
  globalThis.fetch = async (url, init) => { requests.push({ url, ...init }); return new Response('[]', { headers: { 'Content-Type': 'application/json' } }); };
  const load = createModuleLoader(); load(new URL('../api/identity.ts', import.meta.url)).setSessionIdentity(who());
  const { api } = load(new URL('../api/client.ts', import.meta.url));
  await api.vsphereRuns('source/a'); await api.vsphereRun('source/a', 'run?b'); await api.vsphereCollect('source/a');
  assert.deepEqual(requests.map(r => [r.method, r.url]), [
    ['GET', '/api/v1/discovery/vsphere/source%2Fa/runs?limit=20'],
    ['GET', '/api/v1/discovery/vsphere/source%2Fa/runs/run%3Fb'],
    ['POST', '/api/v1/discovery/vsphere/source%2Fa/collect'],
  ]);
});
