import { permissionFixture } from './permissionTestSupport.mjs';
import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluate, helpers, mount, proposal, ui } from '../lib/rollbackTestSupport.mjs';
import { approvalFixture, protectedProposal, vote, session } from '../lib/approvalTestSupport.mjs';

async function setup(t, state, flags = {}) {
  const calls = [];
  const permissions = permissionFixture();
  const actions = { approve: (p) => calls.push(['approve', p.id]), deny() {}, apply: (p) => calls.push(['apply', p.id]), rollback() {}, openFinding() {},
    impact: (p, inspectOnly) => calls.push(['impact', p.id, inspectOnly]) };
  const props = { p: proposal(state, 'change'), actions, ...flags };
  const panel = mount((hooks) => evaluate(new URL('./ProposalCard.tsx', import.meta.url), {
    react: hooks,
    './ProposalMaintenance': ui, '@mantine/core': ui, '../lib/format': { fmtAgo: () => 'earlier', fmtZonedTime: (value) => value, label: (value) => value },
    '../lib/proposalHistory': helpers,
    './PermissionGate': permissions.imports, './ApplyTimeline': ui, './CitationChips': ui, './ProposalDiff': ui, './ProposalPlan': ui, './FixPanel': ui, './common': ui,
    './ApprovalProgress': ui, '../lib/proposalApprovals': approvalFixture(flags.identity),
  }).ProposalCard, props);
  t.after(() => panel.unmount());
  await panel.settle();
  return { ...panel, calls, update: (next) => panel.rerender(Object.assign(props, next)) };
}

test('maintenance hold disables ordinary apply, including an invoked disabled handler', async (t) => {
  const p = { ...proposal('approved', 'change'), maintenance: { allowed: false, status: 'held' } };
  const panel = await setup(t, 'approved', { p });
  const apply = panel.find(node => node.props?.children === 'Apply');
  assert.equal(apply.props.disabled, true);
  apply.props.onClick();
  assert.deepEqual(panel.calls, []);
});

test('retained ordinary apply handler cannot cross a new maintenance hold', async (t) => {
  const panel = await setup(t, 'approved');
  const staleApply = panel.button('Apply').props.onClick;
  await panel.update({ p: { ...proposal('approved', 'change'), maintenance: { allowed: false, status: 'held' } } });
  staleApply(); await panel.settle();
  assert.deepEqual(panel.calls, []);
});

test('risk hold disables apply and a retained handler cannot invoke it', async (t) => {
  const p = proposal('approved', 'change');
  p.finding = { ...p.finding, review: { active: true, suppressed: false, remediation_held: true,
    disposition: 'risk_accepted', current: { reason: 'Temporary constraint' } } };
  const panel = await setup(t, 'approved', { p });
  const apply = panel.find(node => node.props?.children === 'Apply');
  assert.equal(apply.props.disabled, true);
  apply.props.onClick();
  assert.deepEqual(panel.calls, []);
  assert.ok(panel.find(node => node.props?.title === 'Remediation held by risk acceptance'));
});

test('impact action is under the disruption question and proposed inspection cannot approve', async (t) => {
  const panel = await setup(t, 'proposed');
  const question = panel.find((node) => node.props?.title === 'Could it break something');
  assert.ok(question.props.children.some((node) => node?.type === 'Group'));
  await panel.click('Assess impact');
  assert.deepEqual(panel.calls, [['impact', 'change', true]]);
  await panel.click('Approve');
  assert.deepEqual(panel.calls.at(-1), ['approve', 'change']);
});

test('approved review is separate from apply and supports a new receipt', async (t) => {
  const panel = await setup(t, 'approved');
  await panel.click('Review impact before apply');
  assert.deepEqual(panel.calls, [['impact', 'change', false]]);
  await panel.click('Apply');
  assert.deepEqual(panel.calls.at(-1), ['apply', 'change']);
});

test('active impact controls respect action and busy gates, while historical receipts stay readable', async (t) => {
  for (const [state, name] of [['proposed', 'Assess impact'], ['approved', 'Review impact before apply']]) {
    const blocked = await setup(t, state, { actionsDisabled: true });
    assert.equal(blocked.button(name).props.disabled, true);
    const busy = await setup(t, state, { busy: true });
    assert.equal(busy.button(name).props.disabled, true);
  }
  const history = await setup(t, 'rolled_back', { actionsDisabled: true });
  await history.click('View impact receipt');
  assert.deepEqual(history.calls, [['impact', 'change', true]]);
  assert.ok(!history.nodes().some((node) => node.type === 'Button' && ['Approve', 'Apply', 'Review impact before apply', 'Assess impact'].includes(node.props.children)));
});

test('partial proposal has no apply action and proposer or duplicate cannot invoke approve', async (t) => {
  const p = protectedProposal({ approvals: [vote()], assessment: vote().assessment });
  for (const identity of [session(), session('proposer')]) {
    const panel = await setup(t, 'proposed', { p, identity });
    assert.equal(panel.button('Approve').props.disabled, true);
    assert.match(panel.button('Approve').props.reason, /already recorded|You proposed/);
    panel.button('Approve').props.onClick(); await panel.settle();
    assert.deepEqual(panel.calls, []);
    assert.ok(!panel.nodes().some(n => n.type === 'Button' && n.props.children === 'Apply'));
  }
  const next = await setup(t, 'proposed', { p, identity: session('reviewer-2') });
  await next.click('Approve');
  assert.deepEqual(next.calls, [['approve', 'change']]);
});

test('protected approved card keeps apply separate and offers only the bound impact receipt', async (t) => {
  const p = protectedProposal({ state: 'approved', approvals: [vote(), vote('reviewer-2')], assessment: vote().assessment });
  const panel = await setup(t, 'approved', { p, identity: session('reviewer-2') });
  await panel.click('View impact receipt');
  assert.deepEqual(panel.calls, [['impact', 'change', true]]);
  await panel.click('Apply');
  assert.deepEqual(panel.calls.at(-1), ['apply', 'change']);
});
