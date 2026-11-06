import { permissionFixture } from './permissionTestSupport.mjs';
import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluate, helpers, mount, proposal, ui } from '../lib/rollbackTestSupport.mjs';

async function setup(t, state, flags = {}) {
  const calls = [];
  const permissions = permissionFixture();
  const actions = { approve: (p) => calls.push(['approve', p.id]), deny() {}, apply: (p) => calls.push(['apply', p.id]), rollback() {}, openFinding() {},
    impact: (p, inspectOnly) => calls.push(['impact', p.id, inspectOnly]) };
  const panel = mount(() => evaluate(new URL('./ProposalCard.tsx', import.meta.url), {
    '@mantine/core': ui, '../lib/format': { fmtAgo: () => 'earlier', fmtZonedTime: (value) => value, label: (value) => value },
    '../lib/proposalHistory': helpers, '../lib/findingAssurance': { isSuppressed: () => false },
    './PermissionGate': permissions.imports, './ApplyTimeline': ui, './CitationChips': ui, './ProposalDiff': ui, './ProposalPlan': ui, './FixPanel': ui, './common': ui,
  }).ProposalCard, { p: proposal(state, 'change'), actions, ...flags });
  t.after(() => panel.unmount());
  await panel.settle();
  return { ...panel, calls };
}

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
