import assert from 'node:assert/strict';
import test from 'node:test';
import { errorText, evaluate, mount, proposal, ui } from '../lib/rollbackTestSupport.mjs';

const ackLabel = 'I reviewed the risks, unknowns, checks and rollback limitations';
const bypassLabel = 'Proceed without a dependency assessment and record my reason';
const noteLabel = 'Review note and treatment of unresolved dependencies';
const reasonLabel = 'Reason for proceeding without assessment';
const receipt = (id = 'latest', extra = {}) => ({
  id, proposal_id: 'change', generated_at: new Date().toISOString(),
  valid_until: new Date(Date.now() + 600_000).toISOString(),
  fix_sha256: 'bound-fix', evidence_packet: { mode: 'live', complete: false, evidence: [] },
  assessment: { risk_level: 'unknown', summary: 'Dependencies remain unresolved.', risks: [], dependencies: [],
    unknowns: ['A dependent service was not observed.'], required_checks: ['Check management access.'], rollback_limits: ['Recovery is not assured.'] },
  model: { used: false, validated: false, fallback_reason: 'not_configured' },
  freshness: { stale: false, reasons: [], unknowns: [] }, ...extra,
});

async function setup(t, options = {}) {
  const p = options.proposal ?? proposal('proposed', 'change');
  const calls = [], changes = [];
  let closed = 0;
  const context = { actor: 'IT1 Operator', status: { kill: { engaged: false } } };
  const api = {
    async latestImpact(id) { calls.push(['latest', id]); if (options.readError) throw new Error(options.readError); return { assessment: options.receipt ?? null }; },
    async impactReceipt(id) { calls.push(['receipt', id]); if (options.readError) throw new Error(options.readError); return options.receipt ?? receipt(id); },
    async assessImpact(...args) { calls.push(['assess', ...args]); if (options.assess) return options.assess(); return receipt('collected'); },
    async approve(...args) { calls.push(['approve', ...args]); if (options.saveError) throw new Error(options.saveError); return { ...p, state: 'approved' }; },
    async reviewImpact(...args) { calls.push(['review', ...args]); if (options.saveError) throw new Error(options.saveError); return p; },
  };
  const props = {
    proposal: p, inspectOnly: options.inspectOnly ?? false,
    onClose: () => { closed++; }, onChanged: (updated) => changes.push(updated),
  };
  const panel = mount((hooks) => evaluate(new URL('./ImpactReview.tsx', import.meta.url), {
    react: hooks, '@mantine/core': ui, '../api/client': { api, errorText },
    '../lib/format': { fmtZonedTime: (at) => at, label: (value) => value },
    '../state/AppState': { useAppState: () => context },
    './ActorChip': { actorProblem: (actor) => actor ? null : 'Set an acting name.' }, './common': ui,
  }).ImpactReview, props);
  t.after(() => panel.unmount());
  await panel.settle();
  return { ...panel, props, calls, changes, context, closed: () => closed,
    details: () => panel.nodes().find((node) => node.type?.name === 'ImpactDetails')?.props,
  };
}

test('opening an active impact review only reads latest; collection is explicit', async (t) => {
  const panel = await setup(t, { inspectOnly: true });
  assert.deepEqual(panel.calls, [['latest', 'change']]);
  assert.ok(!panel.nodes().some((node) => node.type === 'Textarea'));
  await panel.change('Use stored declarations only; do not contact the target', true);
  await panel.click('Collect and assess dependencies');
  assert.deepEqual(panel.calls, [['latest', 'change'], ['assess', 'change', false]]);
  assert.equal(panel.details().receipt.id, 'collected');
  assert.equal(panel.changes.length, 0);
});

test('approval without assessment requires an explicit reason and opt-in', async (t) => {
  const panel = await setup(t);
  assert.equal(panel.button('Approve reviewed change').props.disabled, true);
  await panel.change(noteLabel, 'A detailed reason alone is not consent.');
  assert.equal(panel.button('Approve reviewed change').props.disabled, true);
  await panel.change(bypassLabel, true);
  await panel.change(reasonLabel, 'Short');
  assert.equal(panel.button('Approve as not assessed').props.disabled, true);
  await panel.change(reasonLabel, '  Known maintenance window; operator accepts the unknowns.  ');
  await panel.click('Approve as not assessed');
  assert.deepEqual(panel.calls.at(-1), ['approve', 'change', undefined, undefined, 'Known maintenance window; operator accepts the unknowns.']);
  assert.equal(panel.changes.length, 1);
  assert.equal(panel.closed(), 1);
});

test('reviewed approval binds the shown receipt only after acknowledgement and note', async (t) => {
  const panel = await setup(t, { receipt: receipt('reviewed-receipt') });
  await panel.change(noteLabel, 'Check the unresolved service dependency before application.');
  assert.equal(panel.button('Approve reviewed change').props.disabled, true);
  await panel.change(ackLabel, true);
  await panel.click('Approve reviewed change');
  assert.deepEqual(panel.calls.at(-1), ['approve', 'change', undefined, 'reviewed-receipt', 'Check the unresolved service dependency before application.']);
  assert.equal(panel.closed(), 1);
});

test('expired or changed evidence cannot be attached to a decision', async (t) => {
  for (const invalid of [
    receipt('expired', { valid_until: new Date(Date.now() - 60_000).toISOString() }),
    receipt('changed', { freshness: { stale: true, reasons: ['target_changed'], unknowns: [] } }),
  ]) {
    const panel = await setup(t, { receipt: invalid });
    await panel.change(noteLabel, 'Recheck these dependencies before approving.');
    assert.equal(panel.control(ackLabel).props.disabled, true);
    assert.equal(panel.button('Approve reviewed change').props.disabled, true);
    panel.button('Approve reviewed change').props.onClick(); await panel.settle();
    assert.deepEqual(panel.calls, [['latest', 'change']]);
  }
});

test('approved re-review reads latest and records its binding without approval or apply', async (t) => {
  const p = { ...proposal('approved', 'change'), assessment: { status: 'reviewed', id: 'old', note: 'Previous note' } };
  const panel = await setup(t, { proposal: p, receipt: receipt('fresh') });
  assert.deepEqual(panel.calls, [['latest', 'change']]);
  assert.ok(!panel.nodes().some((node) => node.props?.label === bypassLabel));
  await panel.change(noteLabel, 'Reviewed the new evidence and unresolved dependencies.');
  await panel.change(ackLabel, true);
  await panel.click('Record assessment review');
  assert.deepEqual(panel.calls.at(-1), ['review', 'change', 'fresh', 'Reviewed the new evidence and unresolved dependencies.']);
  assert.equal(panel.closed(), 1);
});

test('refreshing an assessment resets prior acknowledgement and does not save', async (t) => {
  const panel = await setup(t, { receipt: receipt('original') });
  await panel.change(noteLabel, 'Review this receipt and remaining uncertainty.');
  await panel.change(ackLabel, true);
  await panel.click('Refresh dependency assessment');
  assert.equal(panel.details().receipt.id, 'collected');
  assert.equal(panel.control(ackLabel).props.checked, false);
  assert.equal(panel.button('Approve reviewed change').props.disabled, true);
  assert.deepEqual(panel.calls, [['latest', 'change'], ['assess', 'change', true]]);
});

test('a different proposal cannot inherit the previous acknowledgement or reason', async (t) => {
  const panel = await setup(t, { receipt: receipt('original') });
  await panel.change(noteLabel, 'Reviewed this proposal and its unresolved dependencies.');
  await panel.change(ackLabel, true);
  await panel.rerender({ ...panel.props, proposal: proposal('proposed', 'next') });
  assert.equal(panel.control(ackLabel).props.checked, false);
  assert.equal(panel.control(bypassLabel).props.checked, false);
  assert.equal(panel.control(noteLabel).props.value, '');
  assert.equal(panel.button('Approve reviewed change').props.disabled, true);
  assert.deepEqual(panel.calls, [['latest', 'change'], ['latest', 'next']]);
});

test('historical views load the exact attached receipt and expose no collection or approval', async (t) => {
  for (const state of ['applied', 'verified', 'failed', 'rolled_back', 'denied', 'cancelled']) {
    const p = { ...proposal(state, 'change'), assessment: { status: 'reviewed', id: 'attached', note: 'Original review' } };
    const panel = await setup(t, { proposal: p, inspectOnly: true, receipt: receipt('attached', {
      valid_until: new Date(Date.now() - 60_000).toISOString(), freshness: { stale: true, reasons: ['expired'], unknowns: [] },
    }) });
    assert.deepEqual(panel.calls, [['receipt', 'attached']]);
    assert.equal(panel.details().receipt.id, 'attached');
    assert.equal(panel.details().historical, true);
    assert.ok(!panel.nodes().some((node) => ['Button', 'Checkbox', 'Textarea'].includes(node.type)));
  }
});

test('history without an attached receipt is explicitly unassessed and never reads latest', async (t) => {
  for (const assessment of [undefined, { status: 'not_assessed', id: null, note: 'Earlier operator decision' }]) {
    const panel = await setup(t, { proposal: { ...proposal('verified', 'change'), assessment }, inspectOnly: true });
    assert.deepEqual(panel.calls, []);
    assert.equal(panel.details(), undefined);
    assert.ok(panel.nodes().some((node) => node.props?.children === 'No dependency assessment was attached to this earlier decision.'));
    assert.ok(!panel.nodes().some((node) => ['Button', 'Checkbox', 'Textarea'].includes(node.type)));
  }
});

test('failure reading a historical receipt is visible and never replaced by latest', async (t) => {
  const panel = await setup(t, { proposal: { ...proposal('rolled_back', 'change'), assessment: { status: 'reviewed', id: 'missing', note: 'Old note' } }, inspectOnly: true, readError: 'Receipt could not be loaded' });
  assert.deepEqual(panel.calls, [['receipt', 'missing']]);
  assert.ok(panel.nodes().some((node) => node.type === 'Alert' && node.props.children === 'Receipt could not be loaded'));
  assert.ok(panel.nodes().some((node) => node.type === 'Alert' && node.props.title === 'Assessment unavailable'));
  assert.ok(!panel.nodes().some((node) => node.props?.children === 'No dependency assessment was attached to this earlier decision.'));
  assert.equal(panel.details(), undefined);
});

test('historical expiry describes the recorded decision rather than current readiness', async () => {
  const panel = mount(() => evaluate(new URL('./ImpactReview.tsx', import.meta.url), {
    '@mantine/core': ui, '../api/client': {}, '../lib/format': { fmtZonedTime: (at) => at, label: (value) => value },
    '../state/AppState': {}, './ActorChip': {}, './common': ui,
  }).ImpactDetails, { historical: true, receipt: receipt('old', { freshness: { stale: true, reasons: ['expired'], unknowns: [] } }) });
  await panel.settle();
  const warning = panel.find((node) => node.type === 'Alert' && node.props.title === 'Historical assessment');
  assert.ok(warning.props.children.includes('This receipt records the earlier decision and does not describe current readiness.'));
  panel.unmount();
});

test('kill and actor changes block collection and saving while a review is open', async (t) => {
  const panel = await setup(t, { receipt: receipt() });
  await panel.change(noteLabel, 'Review note with unresolved dependencies.');
  await panel.change(ackLabel, true);
  for (const blocked of [{ actor: '', status: { kill: { engaged: false } } }, { actor: 'IT1 Operator', status: { kill: { engaged: true } } }, { actor: 'IT1 Operator', status: null }]) {
    Object.assign(panel.context, blocked); await panel.rerender();
    assert.equal(panel.button('Refresh dependency assessment').props.disabled, true);
    assert.equal(panel.button('Approve reviewed change').props.disabled, true);
    panel.button('Approve reviewed change').props.onClick();
    panel.button('Refresh dependency assessment').props.onClick();
    await panel.settle();
  }
  assert.deepEqual(panel.calls, [['latest', 'change']]);
});

test('collection busy guards and save failures preserve the review for retry', async (t) => {
  let finish;
  const panel = await setup(t, { assess: () => new Promise((resolve) => { finish = resolve; }), saveError: 'Receipt became stale; collect again' });
  await panel.click('Collect and assess dependencies');
  assert.equal(panel.find((node) => node.type === 'Modal').props.closeOnEscape, false);
  panel.find((node) => node.type === 'Modal').props.onClose();
  assert.equal(panel.closed(), 0);
  assert.equal(panel.button('Approve reviewed change').props.disabled, true);
  finish(receipt('collected')); await panel.settle();
  await panel.change(noteLabel, 'Operator reviewed the collected dependencies.');
  await panel.change(ackLabel, true);
  await panel.click('Approve reviewed change');
  assert.equal(panel.closed(), 0);
  assert.equal(panel.changes.length, 0);
  assert.ok(panel.nodes().some((node) => node.type === 'Alert' && node.props.children === 'Receipt became stale; collect again'));
});
