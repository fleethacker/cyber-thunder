import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluate } from '../lib/moduleTestSupport.mjs';
import { permissionFixture } from './permissionTestSupport.mjs';

const compile = (path) => new URL(path, import.meta.url);
const panelSource = compile('./FindingReviewPanel.tsx');
const helperSource = compile('../lib/findingAssurance.ts');
const clientSource = compile('../api/client.ts');

const helpers = evaluate(helperSource, {});
const { ApiError, errorText } = evaluate(clientSource, {});
const ui = new Proxy({}, { get: (_, name) => name });
const sameDeps = (a, b) => !!a && !!b && a.length === b.length && a.every((v, i) => Object.is(v, b[i]));

// Shallow component harness: runs the real component's hooks, effects and event handlers.
// Widgets/context are stubbed; requests and state stay in memory, with no browser or network.
function mount(server) {
  const permissions = permissionFixture();
  let authority = 1;
  const cells = [];
  let index = 0, dirty = true, tree, pendingEffects = [];
  const hooks = {
    useState(initial) {
      const slot = index++;
      const cell = cells[slot] ??= { value: typeof initial === 'function' ? initial() : initial };
      return [cell.value, (update) => {
        const next = typeof update === 'function' ? update(cell.value) : update;
        if (!Object.is(next, cell.value)) { cell.value = next; dirty = true; }
      }];
    },
    useRef(initial) { return cells[index++] ??= { current: initial }; },
    useCallback(fn, deps) {
      const slot = index++;
      if (!sameDeps(cells[slot]?.deps, deps)) cells[slot] = { value: fn, deps };
      return cells[slot].value;
    },
    useEffect(effect, deps) {
      const slot = index++;
      const previous = cells[slot];
      if (!sameDeps(previous?.deps, deps)) {
        const cell = cells[slot] = { deps };
        pendingEffects.push(() => { previous?.cleanup?.(); cell.cleanup = effect(); });
      }
    },
  };
  const notices = [], puts = [];
  let history = structuredClone(server);
  const currentFinding = () => ({ id: 'finding-one', status: 'open', scanner_status: 'open', evidence: `Evidence ${history.evidence_fingerprint}`, review: structuredClone(history) });
  let rejectNext = false;
  const api = {
    finding: async () => currentFinding(),
    findingReview: async () => structuredClone(history),
    saveFindingReview: async (id, body) => {
      puts.push({ id, body });
      if (rejectNext) { rejectNext = false; throw new ApiError(409, 'Review changed'); }
      assert.equal(body.expected_revision, history.revision);
      assert.equal(body.evidence_fingerprint, history.evidence_fingerprint);
      history = { ...history, revision: history.revision + 1, disposition: body.disposition,
        active: body.disposition !== 'unreviewed', suppressed: ['false_positive', 'not_applicable'].includes(body.disposition) };
      return structuredClone(history);
    },
    acceptFindingRisk: async (id, body) => {
      puts.push({ id, body, operation: 'accept' });
      history = { ...history, revision: history.revision + 1, active: true, suppressed: false,
        disposition: 'risk_accepted', remediation_held: true, risk_acceptance_status: 'active',
        current: { ...body, id: 'risk', disposition: 'risk_accepted', reviewed_at: '2026-11-06T12:00:00Z', reviewed_by: 'IT1 Reviewer' } };
      return structuredClone(history);
    },
    revokeFindingRisk: async (id, body) => {
      puts.push({ id, body, operation: 'revoke' });
      history = { ...history, revision: history.revision + 1, active: false, disposition: 'unreviewed',
        remediation_held: false, risk_acceptance_status: 'revoked', current: { ...body, disposition: 'risk_revoked' } };
      return structuredClone(history);
    },
  };
  const { FindingReviewPanel } = evaluate(panelSource, {
    react: hooks, '@mantine/core': ui, '@mantine/notifications': { notifications: { show: (notice) => notices.push(notice) } },
    '../api/client': { api, ApiError, errorText }, '../lib/findingAssurance': helpers,
    '../api/identity': { authorityRevision: () => authority }, './PermissionGate': permissions.imports,
    '../lib/format': { fmtTime: (value) => value }, '../state/AppState': { useAppState: () => ({ actor: 'IT1 Reviewer', status: { kill: { engaged: false } } }) },
    './ActorChip': { actorProblem: () => null }, './common': ui, './FindingAssurance': ui,
  });
  const props = { finding: currentFinding(), opened: true, onToggle() {}, onFinding(finding) { props.finding = finding; dirty = true; } };
  function render() {
    dirty = false; index = 0; pendingEffects = [];
    tree = FindingReviewPanel(props);
    const effects = pendingEffects; pendingEffects = [];
    effects.forEach((effect) => effect());
  }
  async function settle() {
    for (let pass = 0; pass < 30; pass++) {
      if (dirty) render();
      await new Promise((resolve) => setImmediate(resolve));
      if (!dirty) return;
    }
    throw new Error('Component did not settle');
  }
  function nodes(value) {
    if (Array.isArray(value)) return value.flatMap((child) => nodes(child));
    if (!value || typeof value !== 'object') return [];
    return [value, ...nodes(value.props?.children)];
  }
  const find = (predicate) => {
    const result = nodes(tree).find(predicate);
    assert.ok(result, 'Expected component control');
    return result;
  };
  const control = (label) => find((node) => node.props?.label === label);
  const button = (label) => find((node) => node.type === 'Button' && node.props.children === label);
  const change = async (label, value) => {
    const node = control(label);
    assert.ok(!node.props.disabled, `${label} must be editable`);
    node.props.onChange(node.type === 'Select' ? value : { currentTarget: { value, checked: value } });
    await settle();
  };
  return {
    settle, control, button, puts, notices,
    permissions: permissions.state, changeAuthority() { authority++; },
    change,
    async click(label) { const node = button(label); assert.ok(!node.props.disabled); node.props.onClick(); await settle(); },
    async reopen() { props.opened = false; dirty = true; await settle(); props.opened = true; dirty = true; await settle(); },
    async submit() { find((node) => node.type === 'form').props.onSubmit({ preventDefault() {} }); await settle(); },
    update(next) { history = structuredClone(next); },
    rejectNextSave() { rejectNext = true; },
    async acknowledge(checked = true) { await change('I have reviewed the current evidence and review history', checked); },
    draft() { return { disposition: control('Review decision').props.value, reason: control('Reason').props.value,
      supportingEvidence: control('Supporting evidence').props.value, expiresAt: nodes(tree).find((node) => node.props?.type === 'datetime-local').props.value }; },
    unmount() { cells.forEach((cell) => cell.cleanup?.()); },
  };
}

const baseline = { revision: 1, evidence_fingerprint: 'a'.repeat(64), disposition: 'unreviewed', active: false, suppressed: false,
  current: null, history: [], history_count: 0, reopened_reason: null, identity_verified: false };
const investigation = { ...baseline, revision: 2, disposition: 'needs_investigation', active: true };
const refresh = 'Refresh current evidence and history';
const dismissal = { disposition: 'false_positive', reason: 'Checked the baseline before refresh', supportingEvidence: 'Operator notes to retain', expiresAt: '2099-11-06T12:00' };
async function setup() {
  const panel = mount(baseline);
  await panel.settle();
  await panel.change('Review decision', dismissal.disposition);
  await panel.change('Reason', dismissal.reason);
  await panel.change('Supporting evidence', dismissal.supportingEvidence);
  await panel.change('Expiry (required)', dismissal.expiresAt);
  assert.equal(panel.button('Save review').props.disabled, false);
  return panel;
}

for (const trigger of ['refresh', 'reopen']) {
  for (const changed of ['revision', 'fingerprint']) {
    test(`${trigger} retains dismissal input and blocks save when ${changed} changes, even when both GETs agree`, async () => {
      const panel = await setup();
      try {
        const next = changed === 'revision' ? investigation : { ...baseline, evidence_fingerprint: 'b'.repeat(64) };
        panel.update(next);
        if (trigger === 'refresh') await panel.click(refresh); else await panel.reopen();
        assert.deepEqual(panel.draft(), dismissal);
        assert.equal(panel.button('Save review').props.disabled, true);
        await panel.submit();
        assert.equal(panel.puts.length, 0, 'No overwrite before explicit acknowledgement');
        await panel.acknowledge();
        assert.equal(panel.button('Save review').props.disabled, false);
        await panel.submit();
        assert.equal(panel.puts.length, 1);
        assert.equal(panel.puts[0].body.expected_revision, next.revision);
        assert.equal(panel.puts[0].body.evidence_fingerprint, next.evidence_fingerprint);
        assert.equal(panel.puts[0].body.reason, dismissal.reason);
        assert.deepEqual(panel.draft(), dismissal);
      } finally { panel.unmount(); }
    });
  }
}

test('repeated refresh and Return to Unreviewed do not silently adopt unacknowledged tokens', async () => {
  const panel = await setup();
  try {
    panel.update(investigation);
    await panel.click(refresh);
    await panel.click(refresh);
    await panel.click('Return to Unreviewed');
    assert.equal(panel.button('Save review').props.disabled, true);
    await panel.submit();
    assert.equal(panel.puts.length, 0);
    await panel.acknowledge();
    await panel.click(refresh);
    assert.equal(panel.button('Save review').props.disabled, false, 'Unchanged acknowledged evidence can be saved');
    panel.update({ ...investigation, revision: 3 });
    await panel.click(refresh);
    assert.equal(panel.button('Save review').props.disabled, true, 'A further revision requires a new acknowledgement');
  } finally { panel.unmount(); }
});

test('unchanged refresh retains the draft and allows a normal save without acknowledgement', async () => {
  const panel = await setup();
  try {
    await panel.click(refresh);
    assert.deepEqual(panel.draft(), dismissal);
    assert.equal(panel.button('Save review').props.disabled, false);
    await panel.submit();
    assert.equal(panel.puts.length, 1);
    await panel.click(refresh);
    assert.equal(panel.button('Save review').props.disabled, false, 'A successful save advances the draft base');
  } finally { panel.unmount(); }
});

test('409 retains input and acknowledgement applies only to the refreshed evidence', async () => {
  const panel = await setup();
  try {
    panel.update(investigation);
    panel.rejectNextSave();
    await panel.submit();
    assert.equal(panel.puts.length, 1);
    assert.deepEqual(panel.draft(), dismissal);
    assert.equal(panel.button('Save review').props.disabled, true);
    await panel.acknowledge();
    await panel.submit();
    assert.equal(panel.puts.length, 2);
    assert.equal(panel.puts[1].body.expected_revision, 2);
  } finally { panel.unmount(); }
});

test('withdrawing acknowledgement keeps save blocked across another refresh', async () => {
  const panel = await setup();
  try {
    panel.update(investigation);
    await panel.click(refresh);
    await panel.acknowledge();
    await panel.acknowledge(false);
    await panel.click(refresh);
    assert.equal(panel.button('Save review').props.disabled, true);
    await panel.submit();
    assert.equal(panel.puts.length, 0);
    assert.deepEqual(panel.draft(), dismissal);
  } finally { panel.unmount(); }
});

test('review reopening also requires acknowledgement when revision and fingerprint stay unchanged', async () => {
  const panel = await setup();
  try {
    panel.update({ ...baseline, reopened_reason: 'The review expired; a new review is required.' });
    await panel.click(refresh);
    assert.equal(panel.button('Save review').props.disabled, true);
    await panel.submit();
    assert.equal(panel.puts.length, 0);
    assert.deepEqual(panel.draft(), dismissal);
  } finally { panel.unmount(); }
});

test('acceptance and reasoned reversal use their own endpoints and cannot submit a generic review while held', async () => {
  const panel = mount(baseline);
  try {
    await panel.settle();
    await panel.change('Review decision', 'risk_accepted');
    await panel.change('Reason', 'Maintenance constraint');
    await panel.change('Supporting evidence', 'Owner schedule');
    await panel.change('Expiry (required)', new Date(Date.now() + 86400000).toISOString().slice(0, 16));
    await panel.submit();
    assert.equal(panel.puts.length, 1);
    assert.equal(panel.puts[0].operation, 'accept');
    assert.equal(panel.button('Accept risk').props.disabled, true);
    await panel.change('Review decision', 'confirmed');
    await panel.submit();
    assert.equal(panel.puts.length, 1);
    await panel.click('Prepare risk revocation');
    assert.equal(panel.button('Revoke risk acceptance').props.disabled, true);
    await panel.change('Reason', 'Window is available');
    await panel.submit();
    assert.equal(panel.puts[1].operation, 'revoke');
    assert.deepEqual(Object.keys(panel.puts[1].body).sort(), ['evidence_fingerprint', 'expected_revision', 'reason']);
  } finally { panel.unmount(); }
});

test('ordinary review permission alone and lost authority cannot submit a risk decision', async () => {
  const panel = mount(baseline);
  try {
    await panel.settle();
    await panel.change('Review decision', 'risk_accepted');
    await panel.change('Reason', 'Reviewed');
    await panel.change('Supporting evidence', 'Owner schedule');
    await panel.change('Expiry (required)', new Date(Date.now() + 86400000).toISOString().slice(0, 16));
    panel.permissions.actions = ['review'];
    await panel.submit();
    assert.equal(panel.puts.length, 0);
    panel.permissions.actions = ['risk.accept'];
    panel.changeAuthority();
    await panel.submit();
    assert.equal(panel.puts.length, 0);
    await panel.click(refresh);
    assert.equal(panel.button('Accept risk').props.disabled, true);
    await panel.acknowledge();
    await panel.submit();
    assert.equal(panel.puts.length, 1);
  } finally { panel.unmount(); }
});

for (const decision of ['risk_accepted', 'confirmed']) {
  test(`${decision}: an account change between refresh and acknowledgement requires another refresh`, async () => {
    const panel = mount(baseline);
    try {
      await panel.settle();
      await panel.change('Review decision', decision);
      await panel.change('Reason', 'Maintenance constraint');
      await panel.change('Supporting evidence', 'Owner schedule');
      if (decision === 'risk_accepted') {
        await panel.change('Expiry (required)', new Date(Date.now() + 86400000).toISOString().slice(0, 16));
      }
      panel.changeAuthority();
      await panel.click(refresh);
      const acknowledge = panel.control('I have reviewed the current evidence and review history').props.onChange;
      panel.changeAuthority();
      acknowledge({ currentTarget: { checked: true } });
      await panel.settle();
      await panel.submit();
      assert.equal(panel.puts.length, 0, 'Evidence loaded under a former account cannot authorize this submission');
      await panel.click(refresh);
      // An old checkbox callback must not acknowledge a newer account's refresh either.
      acknowledge({ currentTarget: { checked: true } });
      await panel.settle();
      await panel.submit();
      assert.equal(panel.puts.length, 0, 'Retained acknowledgement must stay bound to its original account');
      await panel.acknowledge();
      await panel.submit();
      assert.equal(panel.puts.length, 1);
    } finally { panel.unmount(); }
  });
}
