import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluate } from '../lib/moduleTestSupport.mjs';

const ui = new Proxy({}, { get: (_, key) => key });
const review = () => ({ id: 'proposal', title: 'Approved change', host: 'host', state: 'approved', fix_preview: 'reviewed payload',
  maintenance: { status: 'held', allowed: false, reason: 'Outside maintenance window; apply is held.',
    next_eligible_at: '2030-01-02T12:00:00Z', current_window: null,
    override: { binding: 'a'.repeat(64), expires_at: '2030-01-02T12:02:00Z' } } });

function mount() {
  const cells = [], requests = [];
  let index = 0, dirty = true, tree, effects = [];
  let identity = { mode: 'oidc', authenticated: true, permissions: ['apply', 'maintenance.override'],
    principal: { issuer: 'fixture', subject: 'first-user' } };
  const props = { proposalId: 'proposal', disabled: false };
  const hooks = {
    useState(initial) {
      const cell = cells[index++] ??= { value: initial };
      return [cell.value, (next) => { if (!Object.is(cell.value, next)) { cell.value = next; dirty = true; } }];
    },
    useRef(initial) { return cells[index++] ??= { current: initial }; },
    useEffect(effect, deps) {
      const slot = index++, old = cells[slot];
      if (!old || deps.some((v, i) => !Object.is(v, old.deps[i]))) {
        const cell = cells[slot] = { deps };
        effects.push(() => { old?.cleanup?.(); cell.cleanup = effect(); });
      }
    },
  };
  const api = Object.fromEntries(['proposal', 'applyWithMaintenanceOverride'].map((method) => [method,
    (...args) => new Promise((resolve, reject) => requests.push({ method, args, resolve, reject }))]));
  const components = evaluate(new URL('./ProposalMaintenance.tsx', import.meta.url), {
    react: hooks, '@mantine/core': ui, '../api/client': { api, errorText: (e) => e.message },
    '../lib/format': { fmtZonedTime: (v) => v },
    '../state/Identity': { useIdentity: () => ({ identity }) },
    './PermissionGate': { usePermissions: () => ({ can: (actions) => actions.every((a) => identity.permissions.includes(a)) }) },
  });
  const nodes = (value = tree) => Array.isArray(value) ? value.flatMap(nodes) : value && typeof value === 'object'
    ? [value, ...nodes(value.props?.children ?? null)] : [];
  const button = (name) => { const node = nodes().find((n) => n.type === 'Button' && n.props.children === name); assert.ok(node, name); return node; };
  async function settle() {
    for (let i = 0; i < 20; i++) {
      if (dirty) { dirty = false; index = 0; effects = []; tree = components.MaintenanceOverrideButton(props); effects.forEach((e) => e()); }
      await new Promise((resolve) => setImmediate(resolve));
      if (!dirty) return;
    }
    throw new Error('failed to settle');
  }
  return { requests, nodes, button, settle,
    async click(name) { const node = button(name); assert.ok(!node.props.disabled); node.props.onClick(); await settle(); },
    async reason(value) { nodes().find((n) => n.type === 'Textarea').props.onChange({ currentTarget: { value } }); await settle(); },
    async identity(value) { identity = value; dirty = true; await settle(); },
    async close() { nodes().find((n) => n.type === 'Modal').props.onClose(); await settle(); },
    async disabled() { props.disabled = true; dirty = true; await settle(); },
    text() { return JSON.stringify(tree); },
    notice(value) { return JSON.stringify(components.MaintenanceNotice({ value })); },
  };
}

async function reviewed() {
  const panel = mount(); await panel.settle();
  assert.equal(panel.requests.length, 0);
  await panel.click('Review window override');
  assert.equal(panel.requests.length, 0);
  await panel.click('Review current change');
  assert.equal(panel.requests.length, 1);
  panel.requests[0].resolve(review()); await panel.settle();
  assert.equal(panel.button('Apply once with this reason').props.disabled, true);
  await panel.reason('Emergency restoration requested by target owner');
  return panel;
}

for (const message of ['Outside maintenance window', 'Fresh authentication required', 'Review is stale', 'Audit unavailable']) {
  test(`explicit override shows ${message}, clears review and never resubmits`, async () => {
    const panel = await reviewed();
    const click = panel.button('Apply once with this reason').props.onClick;
    click(); click(); await panel.settle();
    assert.equal(panel.requests.length, 2);
    assert.deepEqual(panel.requests[1].args, ['proposal', { ...review().maintenance.override, reason: 'Emergency restoration requested by target owner' }]);
    panel.requests[1].reject(new Error(message)); await panel.settle();
    assert.match(panel.text(), new RegExp(message));
    assert.match(panel.text(), /No request will be resubmitted automatically/);
    assert.equal(panel.nodes().some((n) => n.type === 'Textarea'), false);
    await panel.close(); await panel.click('Review window override');
    assert.equal(panel.requests.length, 2);
    assert.equal(panel.nodes().some((n) => n.type === 'Textarea'), false);
  });
}

test('successful submission is only accepted work, not a claim of completed apply', async () => {
  const panel = await reviewed();
  await panel.click('Apply once with this reason');
  panel.requests[1].resolve({ proposal_id: 'proposal', state: 'applying' }); await panel.settle();
  assert.match(panel.text(), /check the proposal for its final outcome/);
  assert.equal(panel.requests.length, 2);
});

test('account change discards late review and retained submit handler cannot cross accounts', async () => {
  const panel = await reviewed();
  const staleSubmit = panel.button('Apply once with this reason').props.onClick;
  await panel.identity({ mode: 'oidc', authenticated: true, permissions: ['apply'], principal: { subject: 'other-user' } });
  assert.equal(panel.nodes().some((n) => n.type === 'Textarea'), false);
  staleSubmit(); await panel.settle();
  assert.match(panel.text(), /cannot request a maintenance override/);
  assert.equal(panel.requests.length, 1);
});

test('closed review ignores late responses and never submits', async () => {
  const panel = mount(); await panel.settle(); await panel.click('Review window override');
  await panel.click('Review current change'); await panel.close();
  panel.requests[0].resolve(review()); await panel.settle();
  assert.equal(panel.nodes().some((n) => n.type === 'Textarea'), false);
  assert.equal(panel.requests.length, 1);
});

test('held and open schedules explain times and recovery without internal identifiers', () => {
  const panel = mount();
  assert.match(panel.notice(review().maintenance), /Next eligible time/);
  assert.match(panel.notice({ ...review().maintenance, next_eligible_at: null }), /No future eligible time/);
  const open = panel.notice({ ...review().maintenance, status: 'open', allowed: true, current_window: { start: 'start', end: 'end' } });
  assert.match(open, /Apply must start before the end/);
  assert.match(open, /authorized verification or recovery/);
  assert.doesNotMatch(open, /aaaaaaaa|policy_sha256|authorization_id|access.json/);
});
