import assert from 'node:assert/strict';
import test from 'node:test';
import { ApiError, browser, errorText, evaluate, helpers, mount, proposal, ui } from '../lib/rollbackTestSupport.mjs';

async function setup(t, options = {}) {
  const env = options.env ?? browser(t, options.values);
  let rows = options.rows ?? ['applied', 'verified', 'failed', 'rolled_back', 'proposed'].map((state) => proposal(state, state));
  let query = new URLSearchParams(options.query ?? '');
  let listener, keys, rejectRollback = false, readError = false, rollbackEvent = null;
  const calls = [], notices = [];
  const context = { actor: 'IT1 Operator', status: { kill: { engaged: false } }, statusError: null, ...options.context };
  const api = {
    async proposals() { calls.push(['list']); return { proposals: structuredClone(rows) }; },
    async proposal(id) { calls.push(['get', id]); if (readError) throw new Error('Proposal refresh failed'); return structuredClone(rows.find((p) => p.id === id)); },
    async rollback(id) { calls.push(['rollback', id]); if (rejectRollback) throw new ApiError(423, 'Kill switch engaged at the server'); if (rollbackEvent) listener(rollbackEvent); return { proposal_id: id, state: 'rolling_back' }; },
    async approve(id) { calls.push(['approve', id]); return structuredClone(rows.find((p) => p.id === id)); },
    async apply(id) { calls.push(['apply', id]); return options.apply ? options.apply(id) : proposal('applying', id); },
    async bulk(...args) { calls.push(['bulk', ...args]); return { results: [] }; },
  };
  let panel;
  panel = mount((hooks) => {
    const libHooks = evaluate(new URL('../lib/hooks.ts', import.meta.url), { react: hooks, '../api/client': { errorText } });
    const assurance = evaluate(new URL('../lib/findingAssurance.ts', import.meta.url));
    const { actorProblem } = evaluate(new URL('../components/ActorChip.tsx', import.meta.url), { '@mantine/core': ui, '../state/AppState': {} });
    return evaluate(new URL('./Decisions.tsx', import.meta.url), {
      react: hooks, '@mantine/core': ui, '@mantine/hooks': { useHotkeys: (value) => { keys = value; } },
      '@mantine/notifications': { notifications: { show: (notice) => notices.push(notice) } },
      'react-router-dom': { useNavigate: () => () => {}, useSearchParams: () => [query, (value) => { query = value; void panel.rerender(); }] },
      '../api/client': { api, errorText }, '../api/types': { ASSET_TYPES: ['linux'] },
      '../components/ConfirmReasonModal': ui, '../components/common': ui, '../components/FindingDrawer': ui, '../components/ProposalCard': ui,
      '../components/RollbackConfirmation': ui, '../components/ActorChip': { actorProblem },
      '../components/ImpactReview': ui,
      '../lib/format': { ageSeconds: (at) => -Date.parse(at), severityRank: () => 1 }, '../lib/findingAssurance': assurance,
      '../lib/hooks': libHooks, '../lib/proposalHistory': helpers,
      '../state/AppState': { useAppState: () => context, useAuditListener: (fn) => { listener = fn; } },
    }).default;
  });
  env.cleanup(() => panel.unmount());
  await panel.settle();
  const cards = () => panel.nodes().filter((node) => node.type === 'ProposalCard');
  return { ...panel, env, calls, notices, context, cards,
    card: (id) => cards().find((node) => node.props.p.id === id),
    modal: () => panel.find((node) => node.type === 'RollbackConfirmation').props,
    impact: () => panel.nodes().find((node) => node.type === 'ImpactReview')?.props,
    async action(id, name, ...args) { const card = cards().find((node) => node.props.p.id === id); card.props.actions[name](card.props.p, ...args); await panel.settle(); },
    async rollback(id) { const card = cards().find((node) => node.props.p.id === id); card.props.actions.rollback(card.props.p); await panel.settle(); },
    async confirm() { panel.find((node) => node.type === 'RollbackConfirmation').props.onConfirm(); await panel.settle(); },
    async key(key) { keys.find(([name]) => name === key)[1](); await panel.settle(); },
    async event(record) { listener(record); await panel.settle(); },
    async tick() { env.tick(); await panel.settle(); },
    update(next) { rows = next; },
    rejectRollback(value = true) { rejectRollback = value; }, failRead(value = true) { readError = value; },
    duringRollback(event) { rollbackEvent = event; },
  };
}

test('persisted history reloads older completed changes independently of touched IDs', async (t) => {
  const panel = await setup(t);
  assert.deepEqual(panel.cards().map((node) => node.props.p.state), ['proposed']);
  await panel.change('Decision view', 'history');
  assert.deepEqual(new Set(panel.cards().map((node) => node.props.p.state)), new Set(['applied', 'verified', 'failed', 'rolled_back', 'proposed']));
  panel.unmount();
  const reloaded = await setup(t, { env: panel.env });
  assert.equal(reloaded.control('Decision view').props.value, 'history');
  assert.equal(reloaded.cards().length, 5);
  assert.ok(reloaded.calls.every(([kind]) => kind === 'list'));
});

test('search, state and inclusive date filters work across stored history', async (t) => {
  const panel = await setup(t);
  await panel.change('Decision view', 'history');
  await panel.change('Search proposals', 'Web Operator verified');
  assert.deepEqual(panel.cards().map((node) => node.props.p.id), ['verified']);
  await panel.change('Last activity from', '2026-11-01');
  assert.equal(panel.cards().length, 0);
  await panel.click('Clear filters');
  await panel.change('State', ['failed', 'rolled_back']);
  assert.deepEqual(new Set(panel.cards().map((node) => node.props.p.state)), new Set(['failed', 'rolled_back']));
});

test('audit-selected completed proposal is shown despite persisted filters and stays unique', async (t) => {
  const values = new Map([['ct.dec.search', JSON.stringify('no match')], ['ct.dec.host', JSON.stringify(['another-host'])]]);
  const panel = await setup(t, { values, query: 'proposal=verified' });
  assert.equal(panel.control('Decision view').props.value, 'history');
  assert.deepEqual(panel.cards().map((node) => node.props.p.id), ['verified']);
  assert.equal(panel.card('verified').props.focused, true);
  await panel.click('Clear selected proposal');
  assert.equal(panel.cards().length, 0);
  assert.ok(panel.calls.every(([kind]) => kind === 'list'));
});

test('a missing audit-linked proposal is explicit and never creates a write', async (t) => {
  const panel = await setup(t, { query: 'proposal=missing' });
  assert.ok(panel.nodes().some((node) => typeof node.props?.children === 'string' && node.props.children.includes('Proposal missing was not found')));
  assert.ok(panel.calls.every(([kind]) => kind === 'list'));
});

test('rollback requires confirmation, rejects duplicate submission, and polls its current result', async (t) => {
  const panel = await setup(t, { query: 'proposal=verified' });
  await panel.rollback('verified');
  assert.equal(panel.modal().proposal.id, 'verified');
  assert.equal(panel.calls.filter(([kind]) => kind === 'rollback').length, 0);
  panel.modal().onConfirm(); panel.modal().onConfirm();
  await panel.settle();
  assert.deepEqual(panel.calls.filter(([kind]) => kind === 'rollback'), [['rollback', 'verified']]);
  assert.equal(panel.modal().proposal, null);
  assert.equal(panel.card('verified').props.busy, true);
  panel.update([proposal('rolled_back', 'verified')]);
  await panel.tick();
  assert.equal(panel.card('verified').props.p.state, 'rolled_back');
  assert.equal(panel.card('verified').props.busy, false);
});

test('kill/actor gates are rechecked with the confirmation open, and shortcuts do not act behind it', async (t) => {
  const panel = await setup(t, { query: 'proposal=verified' });
  await panel.rollback('verified');
  await panel.key('a');
  assert.equal(panel.calls.filter(([kind]) => kind === 'approve').length, 0);
  panel.context.status.kill.engaged = true;
  await panel.rerender();
  await panel.confirm();
  assert.ok(panel.modal().blockedReason.includes('Kill switch'));
  panel.context.status.kill.engaged = false;
  panel.context.actor = '';
  await panel.rerender();
  await panel.confirm();
  assert.ok(panel.modal().blockedReason.includes('acting name'));
  assert.equal(panel.calls.filter(([kind]) => kind === 'rollback').length, 0);
});

test('recheck of a changed proposal refuses rollback before any POST', async (t) => {
  const panel = await setup(t, { query: 'proposal=verified' });
  await panel.rollback('verified');
  panel.update([proposal('rolled_back', 'verified')]);
  await panel.confirm();
  assert.equal(panel.calls.filter(([kind]) => kind === 'rollback').length, 0);
  assert.match(panel.modal().error, /no longer applied or verified/);
});

test('rollback refusal stays visible inside the confirmation', async (t) => {
  const panel = await setup(t, { query: 'proposal=verified' });
  panel.rejectRollback();
  await panel.rollback('verified');
  await panel.confirm();
  assert.equal(panel.modal().error, 'Kill switch engaged at the server');
  assert.equal(panel.modal().busy, false);
});

test('poll failure and rollback error audit events surface uncertainty instead of success', async (t) => {
  const panel = await setup(t, { query: 'proposal=verified' });
  await panel.rollback('verified'); await panel.confirm();
  panel.failRead();
  await panel.tick();
  assert.ok(panel.nodes().some((node) => node.props?.error?.includes('Completion is not confirmed')));
  await panel.event({ action: 'proposal.rollback_error', subject: 'verified', outcome: 'error', details: { error: 'Restore failed' } });
  assert.ok(panel.nodes().some((node) => node.props?.error?.includes('Restore failed')));
  assert.equal(panel.card('verified').props.busy, false);
});

test('an early rollback failure event is not lost before the request response arrives', async (t) => {
  const panel = await setup(t, { query: 'proposal=verified' });
  panel.duringRollback({ action: 'proposal.rollback_error', subject: 'verified', outcome: 'error', details: { error: 'Early restore failure' } });
  await panel.rollback('verified'); await panel.confirm();
  assert.ok(panel.nodes().some((node) => node.props?.error?.includes('Early restore failure')));
  assert.equal(panel.card('verified').props.busy, false);
});

test('successful progress reads clear transient read errors without hiding command errors', async (t) => {
  const panel = await setup(t, { query: 'proposal=verified' });
  await panel.rollback('verified'); await panel.confirm();
  panel.failRead(); await panel.tick();
  assert.ok(panel.nodes().some((node) => node.props?.error?.includes('Completion is not confirmed')));
  panel.failRead(false); panel.update([proposal('rolled_back', 'verified')]);
  await panel.tick();
  assert.ok(!panel.nodes().some((node) => node.props?.error?.includes('Completion is not confirmed')));
  assert.equal(panel.card('verified').props.p.state, 'rolled_back');
});

test('failed proposal with a snapshot reference does not open rollback confirmation', async (t) => {
  const panel = await setup(t, { query: 'proposal=failed' });
  await panel.rollback('failed');
  assert.equal(panel.modal().proposal, null);
  assert.equal(panel.calls.filter(([kind]) => kind === 'rollback').length, 0);
});

test('approve button and keyboard open review without making an approval request', async (t) => {
  const panel = await setup(t, { rows: [proposal('proposed', 'one')] });
  await panel.action('one', 'approve');
  assert.equal(panel.impact().proposal.id, 'one');
  assert.equal(panel.impact().inspectOnly, false);
  panel.impact().onClose(); await panel.settle();
  await panel.key('a');
  assert.equal(panel.impact().proposal.id, 'one');
  assert.deepEqual(panel.calls, [['list']]);
});

test('all queue shortcuts and direct mutations are blocked behind impact review', async (t) => {
  const panel = await setup(t, { rows: [proposal('proposed', 'one'), proposal('proposed', 'two'), proposal('approved', 'approved')] });
  await panel.action('one', 'approve');
  const focused = panel.cards().find((card) => card.props.focused).props.p.id;
  for (const key of ['j', 'k', 'a', 'd', 'Enter', 'x']) await panel.key(key);
  await panel.action('approved', 'apply');
  await panel.action('two', 'deny');
  assert.equal(panel.impact().proposal.id, 'one');
  assert.equal(panel.cards().find((card) => card.props.focused).props.p.id, focused);
  assert.ok(panel.cards().every((card) => !card.props.selected));
  assert.equal(panel.find((node) => node.type === 'FindingDrawer').props.findingId, null);
  assert.equal(panel.find((node) => node.type === 'ConfirmReasonModal').props.opened, false);
  assert.deepEqual(panel.calls, [['list']]);
});

test('sequential approval removes only completed selections and cancellation keeps the rest', async (t) => {
  const panel = await setup(t, { rows: [proposal('proposed', 'one'), proposal('proposed', 'two'), proposal('proposed', 'three')] });
  await panel.change('Select proposed (3)', true);
  const reviewSelected = () => panel.nodes().find((node) => node.type === 'Button' && Array.isArray(node.props.children) && node.props.children[0] === 'Review selected (');
  reviewSelected().props.onClick(); await panel.settle();
  assert.equal(panel.impact().proposal.id, 'one');
  assert.equal(panel.impact().inspectOnly, false);
  panel.impact().onClose(); await panel.settle();
  assert.ok(panel.cards().every((card) => card.props.selected));
  await panel.click('Continue selected reviews');
  const callbacks = panel.impact();
  callbacks.onChanged({ ...proposal('approved', 'one'), assessment: { status: 'not_assessed', id: null, note: 'Documented operator reason' } });
  callbacks.onChanged(proposal('approved', 'one'));
  callbacks.onClose(); await panel.settle();
  assert.equal(panel.impact(), undefined, 'No next review or inference opens automatically');
  assert.equal(panel.card('one').props.selected, false);
  assert.equal(panel.card('two').props.selected, true);
  assert.equal(panel.card('three').props.selected, true);
  const progress = panel.nodes().find((node) => node.type === 'Text' && Array.isArray(node.props.children) && node.props.children.includes(' approved. Each proposal needs its own review and decision. Unprocessed proposals remain selected.'));
  assert.equal(progress.props.children[0], 1);
  await panel.click('Continue selected reviews');
  assert.equal(panel.impact().proposal.id, 'two');
  panel.impact().onClose(); await panel.settle();
  await panel.click('End selected reviews');
  assert.equal(panel.card('two').props.selected, true);
  assert.equal(panel.card('three').props.selected, true);
  assert.deepEqual(panel.calls, [['list']], 'No direct or bulk approval API is used');
});

test('a changed next proposal is surfaced without silently approving or dropping its selection', async (t) => {
  const panel = await setup(t, { rows: [proposal('proposed', 'one'), proposal('proposed', 'two')] });
  await panel.change('Select proposed (2)', true);
  panel.nodes().find((node) => node.type === 'Button' && Array.isArray(node.props.children) && node.props.children[0] === 'Review selected (').props.onClick();
  await panel.settle();
  const modal = panel.impact();
  modal.onChanged(proposal('approved', 'one')); modal.onClose(); await panel.settle();
  panel.update([proposal('approved', 'one'), proposal('approved', 'two')]);
  await panel.click('Refresh');
  await panel.click('Continue selected reviews');
  assert.equal(panel.impact(), undefined);
  assert.equal(panel.card('two').props.selected, true);
  assert.ok(panel.nodes().some((node) => node.props?.error?.includes('no longer waiting for approval')));
});

test('approved proposal can bind a refreshed review without automatically applying it', async (t) => {
  const p = { ...proposal('approved', 'one'), assessment: { status: 'reviewed', id: 'earlier', note: 'Earlier review' } };
  const panel = await setup(t, { rows: [p] });
  await panel.action('one', 'impact', false);
  assert.equal(panel.impact().inspectOnly, false);
  const modal = panel.impact();
  modal.onChanged({ ...p, assessment: { ...p.assessment, id: 'refreshed' } }); modal.onClose(); await panel.settle();
  assert.equal(panel.card('one').props.p.assessment.id, 'refreshed');
  assert.deepEqual(panel.calls, [['list']]);
});

test('selected historical risk inspection is read-only and remains available under kill', async (t) => {
  const p = { ...proposal('rolled_back', 'old'), assessment: { status: 'reviewed', id: 'attached', note: 'Original decision' } };
  const panel = await setup(t, { rows: [p], query: 'proposal=old', context: { actor: '', status: { kill: { engaged: true } } } });
  await panel.action('old', 'impact', true);
  assert.equal(panel.impact().inspectOnly, true);
  assert.equal(panel.impact().proposal.assessment.id, 'attached');
  assert.deepEqual(panel.calls, [['list']]);
});

test('actor, kill and unavailable-status gates block opening an active review', async (t) => {
  const panel = await setup(t, { rows: [proposal('proposed', 'one')] });
  for (const blocked of [
    { actor: '', status: { kill: { engaged: false } }, statusError: null },
    { actor: 'IT1 Operator', status: { kill: { engaged: true } }, statusError: null },
    { actor: 'IT1 Operator', status: null, statusError: 'Unavailable' },
    { actor: 'IT1 Operator', status: { kill: { engaged: false } }, statusError: 'Refresh failed' },
  ]) {
    Object.assign(panel.context, blocked); await panel.rerender();
    await panel.action('one', 'approve'); await panel.action('one', 'impact', true); await panel.key('a');
    assert.equal(panel.impact(), undefined);
  }
  assert.deepEqual(panel.calls, [['list']]);
});

test('an in-flight apply blocks opening review for that proposal', async (t) => {
  let finish;
  const panel = await setup(t, { rows: [proposal('approved', 'one')], apply: () => new Promise((resolve) => { finish = resolve; }) });
  await panel.action('one', 'apply');
  await panel.action('one', 'impact', false);
  assert.equal(panel.impact(), undefined);
  assert.equal(panel.card('one').props.busy, true);
  finish(proposal('applied', 'one')); await panel.settle();
});
