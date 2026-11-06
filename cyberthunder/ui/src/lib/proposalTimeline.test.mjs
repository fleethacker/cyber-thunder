import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluate, proposal } from './rollbackTestSupport.mjs';

const { proposalTimeline, proposalAudit } = evaluate(new URL('./proposalTimeline.ts', import.meta.url));
const event = (action, details = {}, outcome = 'ok', seq = 1, subject = 'old-change') =>
  ({ action, details, outcome, seq, subject, actor: 'IT1 Recovery', ts: '2026-11-06T12:00:00Z' });
const steps = (state, records = [], extra = {}) => proposalTimeline({ ...proposal(state), ...extra }, records);
const step = (rows, key) => rows.find((s) => s.key === key);

test('allocated snapshot, failure and unrelated snapshot actions never prove capture', () => {
  for (const state of ['applying', 'applied', 'failed', 'verified', 'rolled_back']) {
    for (const records of [[], [event('remediation.snapshot')], [event('remediation.before_state', {}, 'error')]]) {
      assert.equal(step(steps(state, records), 'before').state, 'pending');
    }
  }
});

test('exact successful before-state receipt confirms capture even when payload was stopped', () => {
  const rows = steps('failed', [event('remediation.before_state')], {
    history: [{ state: 'failed', note: 'stopped before apply: authorization revoked' }],
  });
  assert.equal(step(rows, 'before').state, 'done');
  assert.equal(step(rows, 'applied').state, 'pending');
  assert.equal(step(rows, 'rolled_back').state, 'pending');
});

test('prepayload and postapply failures without a verification result retain unknown stages', () => {
  for (const history of [[], [{ state: 'applied' }]]) {
    const rows = steps('failed', [event('proposal.failed', { note: 'error during verify: capture failed' }, 'failed')], { history });
    assert.equal(step(rows, 'verified').state, 'pending');
    assert.equal(step(rows, 'failed').title, 'Change failed');
    assert.equal(step(rows, 'rolled_back').state, 'pending');
  }
});

test('specific verification failure receipts and explicit result notes identify the failed check', () => {
  for (const records of [[event('remediation.verify', { rule_passed: false }, 'failed')],
    [event('remediation.verify', { error: 'connection lost' }, 'error')],
    [event('proposal.failed', { note: 'verify failed: rule_passed=False health=True' }, 'failed')]]) {
    assert.equal(step(steps('failed', records), 'verified').title, 'Verification failed');
  }
});

test('runbook issuance and missing issuance evidence never assert automated application', () => {
  const rows = steps('applied', [event('remediation.runbook_issued')]);
  assert.equal(step(rows, 'applied').title, 'Runbook issued');
  assert.equal(step(rows, 'verified').state, 'pending');
  const limited = steps('applied', [], { fix: { kind: 'runbook' } });
  assert.equal(step(limited, 'applied').state, 'pending');
  assert.match(step(limited, 'verified').title, /Awaiting operator/);
});

test('old applied state alone does not distinguish payload completion from runbook issuance', () => {
  assert.equal(step(steps('applied', [], { history: [] }), 'applied').state, 'pending');
  const rows = steps('applied', [event('proposal.applied', {
    note: 'applied fixture:fix on host-id; changed=True; file updated',
  })]);
  assert.equal(step(rows, 'applied').state, 'done');
  assert.equal(step(rows, 'applied').title, 'Application recorded');
});

test('manual verification stays pending; only a complete successful check is positive', () => {
  const manual = steps('applied', [event('remediation.verify', { ok: false, rule_passed: null, health: true }, 'manual')]);
  assert.equal(step(manual, 'verified').title, 'Manual verification required');
  assert.equal(step(manual, 'verified').state, 'pending');
  for (const details of [{}, { ok: true, rule_passed: null, health: true }, { ok: true, rule_passed: true, health: false }]) {
    assert.equal(step(steps('applied', [event('remediation.verify', details)]), 'verified').state, 'pending');
  }
  assert.equal(step(steps('applied', [event('remediation.verify', { ok: true, rule_passed: true, health: true })]), 'verified').state, 'done');
});

test('saved verified and rolled-back states survive missing audit without proving preceding milestones', () => {
  assert.equal(step(steps('verified', [], { history: [] }), 'verified').state, 'done');
  const rows = steps('rolled_back', [], { history: [] });
  assert.equal(step(rows, 'rolled_back').state, 'done');
  assert.equal(step(rows, 'before').state, 'pending');
  assert.equal(step(rows, 'applied').state, 'pending');
  assert.equal(step(rows, 'verified').state, 'pending');
  assert.doesNotMatch(step(rows, 'rolled_back').note, /IT1 Approver|by operator/);
});

test('old to/at histories support verification and rollback without inventing a recovery method', () => {
  const at = '2026-10-29T13:00:00Z';
  const rows = steps('rolled_back', [], { history: [
    { to: 'verified', at }, { to: 'rolled_back', at, actor: 'IT2 Restore' },
  ] });
  assert.equal(step(rows, 'verified').ts, at);
  assert.match(step(rows, 'verified').note, /Historical result/);
  assert.match(step(rows, 'rolled_back').note, /IT2 Restore/);
});

test('automatic and manual rollback receipts use only the actual rollback actor', () => {
  for (const [actor, reason] of [['agent', 'verify failed'], ['IT2 Restore', 'manual']]) {
    const rows = steps('failed', [{ ...event('remediation.rollback', { ok: true, reason }), actor }]);
    assert.equal(step(rows, 'rolled_back').state, 'done');
    assert.equal(step(rows, 'rolled_back').note, `Recorded rollback actor: ${actor}.`);
    assert.doesNotMatch(step(rows, 'rolled_back').title, /operator|automatic|manual/i);
  }
});

test('rollback start and mutation boundaries are uncertain outcomes, never active recovery', () => {
  for (const action of ['remediation.rollback_started', 'remediation.rollback_mutation']) {
    const row = step(steps('failed', [event(action)]), 'rolled_back');
    assert.equal(row.state, 'pending');
    assert.equal(row.title, 'Rollback started; outcome unknown');
  }
});

test('failed and blocked rollback supersede earlier starts and are never active or successful', () => {
  for (const failure of [event('proposal.rollback_error', { error: 'kill switch engaged' }, 'error', 3),
    event('remediation.rollback', { ok: false }, 'error', 3),
    event('remediation.rollback_preflight', { status: 'blocked' }, 'blocked', 3),
    event('action.blocked', { action: 'rollback' }, 'blocked', 3)]) {
    const rows = steps('verified', [failure, event('remediation.rollback_started', {}, 'ok', 2)]);
    assert.equal(step(rows, 'rolled_back').state, 'failed');
    assert.doesNotMatch(step(rows, 'rolled_back').title, /Rolling back|Rolled back/);
  }
});

test('new successful rollback supersedes older failure regardless of fetch ordering', () => {
  const rows = steps('failed', [event('remediation.rollback', { ok: true }, 'ok', 4),
    event('proposal.rollback_error', {}, 'error', 2), event('remediation.rollback_started', {}, 'ok', 3)]);
  assert.equal(step(rows, 'rolled_back').state, 'done');
});

test('unrelated and contradictory proposal subjects cannot supply successful evidence', () => {
  const records = ['remediation.before_state', 'proposal.applied', 'proposal.verified', 'proposal.rolled_back']
    .map((action, i) => event(action, { proposal_id: 'old-change' }, 'ok', i, 'other-proposal'));
  assert.deepEqual(proposalAudit(records, 'old-change'), []);
  const rows = steps('failed', records);
  for (const key of ['before', 'applied', 'verified', 'rolled_back']) assert.equal(step(rows, key).state, 'pending');
  assert.equal(proposalAudit([event('maintenance.blocked', { proposal_id: 'old-change' }, 'blocked', 1, null)], 'old-change').length, 1);
});

test('unstarted proposals stay empty unless an exact proposal block is recorded', () => {
  for (const state of ['proposed', 'approved', 'denied', 'cancelled']) assert.deepEqual(steps(state), []);
  const rows = steps('approved', [event('maintenance.blocked', { reason: 'Window closed' }, 'blocked')]);
  assert.equal(step(rows, 'blocked').state, 'failed');
  assert.equal(step(rows, 'start'), undefined);
});

test('new verification failure supersedes old success regardless of array ordering', () => {
  const rows = steps('verified', [event('remediation.verify', { error: 'new failure' }, 'error', 9),
    event('proposal.verified', {}, 'ok', 4)]);
  assert.equal(step(rows, 'verified').state, 'failed');
  assert.equal(step(rows, 'verified').rec.seq, 9);
});

test('new complete verification supersedes old failure and keeps the matching receipt', () => {
  const rows = steps('applied', [event('remediation.verify', { ok: true, rule_passed: true, health: true }, 'ok', 9),
    event('proposal.failed', { note: 'verify failed: rule_passed=False health=True' }, 'failed', 4)]);
  assert.equal(step(rows, 'verified').state, 'done');
  assert.equal(step(rows, 'verified').rec.seq, 9);
});

test('new manual or incomplete verification cannot inherit old success', () => {
  for (const [outcome, details] of [['manual', { ok: false, rule_passed: null, health: true }], ['ok', {}]]) {
    const rows = steps('verified', [event('proposal.verified', {}, 'ok', 3),
      event('remediation.verify', details, outcome, 8)]);
    assert.equal(step(rows, 'verified').state, 'pending');
    assert.equal(step(rows, 'verified').rec.seq, 8);
  }
});

test('dated saved verification can supersede an older failed receipt', () => {
  const rows = steps('verified', [event('remediation.verify', {}, 'failed', 3)], {
    history: [{ state: 'verified', ts: '2026-11-06T13:00:00Z' }],
  });
  assert.equal(step(rows, 'verified').state, 'done');
  assert.equal(step(rows, 'verified').rec, undefined);
});

test('contradictory proposal and target bindings never prove success', () => {
  for (const details of [{ proposal_id: 'other' }, { target_id: 'other' }, { finding_id: 'other' }]) {
    const rows = steps('failed', [event('remediation.before_state', details),
      event('proposal.verified', details, 'ok', 2), event('proposal.rolled_back', details, 'reverted', 3)]);
    for (const key of ['before', 'verified', 'rolled_back']) assert.equal(step(rows, key).state, 'pending');
  }
});

test('malformed and conflicting sequence evidence is excluded without accepting false success', () => {
  const good = event('remediation.before_state');
  const invalid = [null, false, [], {}, { ...good, seq: '1' }, { ...good, seq: -1 },
    { ...good, seq: NaN }, { ...good, seq: 1.5 }, { ...good, action: [] },
    { ...good, details: [] }, { ...good, subject: 0 }, { ...good, actor: {} }, { ...good, ts: {} }];
  assert.deepEqual(proposalAudit(invalid, 'old-change'), []);
  assert.deepEqual(proposalAudit([good, { ...good, outcome: 'error' }], 'old-change'), []);
  assert.equal(proposalAudit([good, { ...good }], 'old-change').length, 1);
});

test('equivalent fetched and streamed objects keep positive evidence despite key order', () => {
  const a = event('remediation.before_state', { copied: 1, files: ['fixture'] });
  const b = { details: { files: ['fixture'], copied: 1 }, ...Object.fromEntries(Object.entries(a).filter(([k]) => k !== 'details').reverse()) };
  assert.equal(proposalAudit([a, b], 'old-change').length, 1);
  assert.equal(step(steps('failed', [a, b]), 'before').state, 'done');
});

test('contradictory success bodies never confirm capture verification or restoration', () => {
  const rows = steps('failed', [event('remediation.before_state', { ok: false }),
    event('proposal.verified', { ok: false }, 'ok', 2),
    event('proposal.rolled_back', { ok: false }, 'reverted', 3)]);
  for (const key of ['before', 'verified', 'rolled_back']) assert.notEqual(step(rows, key).state, 'done');
});

test('a malformed rollback result does not invent a successful start boundary', () => {
  const row = step(steps('failed', [event('remediation.rollback', {})]), 'rolled_back');
  assert.equal(row.state, 'pending');
  assert.equal(row.title, 'Rollback outcome unknown');
});

test('known receipt order wins over saved milestone timestamps when the clock moves backwards', () => {
  const history = [{ state: 'verified', ts: '2026-11-06T14:00:00Z' },
    { state: 'rolled_back', ts: '2026-11-06T14:01:00Z' }];
  const rows = steps('rolled_back', [
    { ...event('proposal.verified', {}, 'ok', 1), ts: '2026-11-06T14:00:00Z' },
    event('remediation.verify', {}, 'failed', 2),
    { ...event('proposal.rolled_back', {}, 'reverted', 3), ts: '2026-11-06T14:01:00Z' },
    event('proposal.rollback_error', {}, 'error', 4),
  ], { history });
  assert.equal(step(rows, 'verified').state, 'failed');
  assert.equal(step(rows, 'rolled_back').state, 'failed');
});

test('a later saved verification failure supersedes older successful checks', () => {
  const rows = steps('failed', [event('proposal.verified', {}, 'ok', 1),
    event('remediation.verify', { ok: true, rule_passed: true, health: true }, 'ok', 2)], {
    history: [{ state: 'failed', ts: '2026-11-06T14:00:00Z', note: 'verify failed: rule_passed=False health=True' }],
  });
  assert.equal(step(rows, 'verified').state, 'failed');
  assert.equal(step(rows, 'verified').rec, undefined);
});
