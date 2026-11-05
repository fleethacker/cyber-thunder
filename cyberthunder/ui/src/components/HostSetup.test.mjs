import assert from 'node:assert/strict';
import test from 'node:test';
import { actorProblem, errorText, evaluate, mount, target, ui } from '../lib/setupTestSupport.mjs';

const runtime = (kind = 'container', runtime_os = 'linux') => ({
  kind, runtime_os, detection: kind === 'native' ? 'no_container_markers' : 'local_markers',
  physical_host_os: 'unknown', host_address: null, host_address_required: true,
  local_transport: { boundary: kind === 'container' ? 'container' : 'runtime', description: 'Local acts inside the service environment.' },
  supported_host_transports: ['ssh', 'winrm'], hints: [],
});
const readiness = (overrides = {}) => ({ target_id: 'fixture-host', ready_for_connection_test: true, checked: 'declarations_only',
  connection_test_route: '/api/v1/targets/fixture-host/discover', checks: [], warnings: [], runtime: runtime(), ...overrides });

async function setup(t, options = {}) {
  const requests = [], local = [], saved = [], busy = [];
  const ctx = { actor: 'IT1 Operator', status: { kill: { engaged: false } }, statusError: null };
  const api = new Proxy(Object.fromEntries(['runtimeContext', 'registerHost', 'targetReadiness', 'discover'].map((kind) => [kind,
    (arg) => new Promise((resolve, reject) => requests.push({ kind, arg, resolve, reject }))])), {
    get(object, name) { assert.ok(name in object, `Unexpected API operation: ${String(name)}`); return object[name]; },
  });
  const panel = mount((hooks) => evaluate(new URL('./HostSetup.tsx', import.meta.url), {
    react: hooks, '@mantine/core': ui, '../api/client': { api, errorText }, './common': ui,
    './setupAccess': evaluate(new URL('./setupAccess.ts', import.meta.url), {
      '../state/AppState': { useAppState: () => ctx }, './ActorChip': { actorProblem },
    }),
  }).HostSetupContent, { onUseLocal: (defaults) => local.push(defaults), onSaved: (value) => saved.push(value), setBusy: (value) => busy.push(value) });
  t.after(() => panel.unmount());
  await panel.settle();
  const respond = async (value, index = requests.length - 1) => { requests[index].resolve(value); await panel.settle(); };
  if (!options.deferredRuntime) await respond(runtime(options.kind, options.os));
  return { ...panel, requests, ctx, local, saved, busy, respond,
    async fill(platform = 'linux', scope = 'out') {
      for (const [label, value] of [['Intended host operating system', platform], ['Inventory ID', 'fixture-host'],
        ['Host display name', 'Deployment host alias'], ['Reachable host address', '10.20.30.40'], ['Host account', 'operator'],
        ['Credential reference name', 'DEPLOYMENT_HOST'], ['Host inventory authorization', scope], ['Host authorization reason', 'Owner reviewed this host']]) await panel.change(label, value);
    },
    async register(scope = 'out') {
      await this.fill('linux', scope); await panel.click('Review host registration'); await panel.click('Confirm host registration');
      await respond(target({ in_scope: scope === 'in' }));
    },
  };
}

test('opening setup reads only runtime markers and never fills a guessed host address or authorization', async (t) => {
  const panel = await setup(t);
  assert.deepEqual(panel.requests.map((r) => r.kind), ['runtimeContext']);
  assert.equal(panel.control('Reachable host address').props.value, '');
  assert.equal(panel.control('Intended host operating system').props.value, null);
  assert.equal(panel.control('Host inventory authorization').props.value, '');
  assert.equal(panel.button('Review host registration').props.disabled, true);
  assert.ok(!panel.nodes().some((node) => node.props?.children === 'Register this service environment for local access'));
});

for (const platform of ['linux', 'windows']) {
  test(`${platform} registration sends only declared host access and explicit scope/reason, without connection or scan`, async (t) => {
    const panel = await setup(t);
    await panel.fill(platform, 'out');
    assert.equal(panel.control('Host port').props.value, platform === 'windows' ? 5986 : 22);
    await panel.click('Review host registration');
    assert.equal(panel.requests.length, 1);
    await panel.click('Confirm host registration');
    const request = panel.requests[1];
    assert.equal(request.kind, 'registerHost');
    assert.deepEqual(request.arg, { id: 'fixture-host', name: 'Deployment host alias', asset_type: platform,
      transport: platform === 'windows' ? 'winrm' : 'ssh', address: '10.20.30.40', port: platform === 'windows' ? 5986 : 22,
      username: 'operator', credential_ref: 'DEPLOYMENT_HOST', sudo: false, in_scope: false, reason: 'Owner reviewed this host' });
    await panel.respond(target(), 1);
    assert.deepEqual(panel.requests.map((r) => r.kind), ['runtimeContext', 'registerHost', 'targetReadiness']);
    assert.equal(panel.saved.length, 1);
    assert.equal(panel.button('Test connection (read asset facts)').props.disabled, true);
  });
}

for (const os of ['linux', 'windows']) {
  test(`native ${os} local choice delegates to explicit inventory review without registering automatically`, async (t) => {
    const panel = await setup(t, { kind: 'native', os });
    await panel.click('Register this service environment for local access');
    assert.deepEqual(panel.local, [{ asset_type: os, transport: 'local', sudo: false }]);
    assert.deepEqual(panel.requests.map((r) => r.kind), ['runtimeContext']);
  });
}

test('Kubernetes and unknown runtime never offer local access as the physical deployment host', async (t) => {
  for (const kind of ['kubernetes', 'unknown']) {
    const panel = await setup(t, { kind });
    assert.ok(!panel.nodes().some((node) => node.props?.children === 'Register this service environment for local access'));
  }
});

test('review rechecks actor/kill and suppresses duplicate registration without overwriting an existing alias', async (t) => {
  const panel = await setup(t);
  await panel.fill(); await panel.click('Review host registration');
  panel.ctx.status.kill.engaged = true; await panel.rerender();
  assert.equal(panel.button('Confirm host registration').props.disabled, true);
  panel.button('Confirm host registration').props.onClick();
  assert.equal(panel.requests.length, 1);
  panel.ctx.status.kill.engaged = false; panel.ctx.actor = ''; await panel.rerender();
  panel.button('Confirm host registration').props.onClick();
  assert.equal(panel.requests.length, 1);
  panel.ctx.actor = 'IT1 Operator'; await panel.rerender();
  const click = panel.button('Confirm host registration').props.onClick;
  click(); click(); await panel.settle();
  assert.equal(panel.requests.length, 2);
  panel.requests[1].reject(new Error('target already exists')); await panel.settle();
  assert.equal(panel.saved.length, 0);
  assert.equal(panel.find((node) => node.type === 'ErrorBox').props.error, 'target already exists');
  assert.equal(panel.button('Confirm host registration').props.disabled, false);
});

test('successful registration does not imply connectivity; the explicit test is a separate guarded operation', async (t) => {
  const panel = await setup(t);
  await panel.register('in');
  assert.equal(panel.button('Test connection (read asset facts)').props.disabled, true);
  await panel.respond(readiness({ connection_test_route: 'https://untrusted.invalid/command' }));
  assert.equal(panel.button('Test connection (read asset facts)').props.disabled, false);
  assert.equal(panel.requests.length, 3);
  const click = panel.button('Test connection (read asset facts)').props.onClick;
  click(); click(); await panel.settle();
  assert.deepEqual(panel.requests[3].arg, 'fixture-host', 'Use the fixed client operation, never a returned arbitrary route');
  assert.equal(panel.requests[3].kind, 'discover');
  assert.equal(panel.requests.length, 4);
  panel.requests[3].reject(new Error('Connection refused')); await panel.settle();
  assert.ok(!panel.nodes().some((node) => node.props?.children === 'Connection test completed'));
  assert.equal(panel.find((node) => node.type === 'ErrorBox').props.error, 'Connection refused');
});

test('out-of-scope and stale readiness cannot authorize an explicit connection test', async (t) => {
  const panel = await setup(t);
  await panel.register('out'); await panel.respond(readiness());
  assert.equal(panel.button('Test connection (read asset facts)').props.disabled, true);
  panel.button('Test connection (read asset facts)').props.onClick(); assert.equal(panel.requests.length, 3);
  const second = await setup(t);
  await second.register('in'); await second.respond(readiness({ target_id: 'other-host' }));
  assert.equal(second.button('Test connection (read asset facts)').props.disabled, true);
  assert.match(second.find((node) => node.type === 'ErrorBox').props.error, /does not match/);
});

test('kill activated after declaration readiness blocks connection, with no fallback probe', async (t) => {
  const panel = await setup(t);
  await panel.register('in'); await panel.respond(readiness());
  panel.ctx.status.kill.engaged = true; await panel.rerender();
  panel.button('Test connection (read asset facts)').props.onClick();
  assert.equal(panel.requests.length, 3);
});

test('inline key paths or incomplete declarations cannot reach guided registration', async (t) => {
  const panel = await setup(t);
  await panel.fill(); await panel.change('Credential reference name', 'C:/keys/secret.pem');
  assert.equal(panel.button('Review host registration').props.disabled, true);
  panel.button('Review host registration').props.onClick();
  assert.equal(panel.requests.length, 1);
});

test('runtime failure is explicit and a closed setup ignores late read-only responses', async (t) => {
  const panel = await setup(t, { deferredRuntime: true });
  panel.requests[0].reject(new Error('Context unavailable')); await panel.settle();
  const error = panel.find((node) => node.type === 'ErrorBox');
  assert.equal(error.props.error, 'Context unavailable');
  error.props.onRetry(); await panel.settle();
  panel.unmount(); await panel.respond(runtime(), 1);
  assert.equal(panel.lateWrites(), 0);
  assert.equal(panel.requests.length, 2);
});
