import assert from 'node:assert/strict';
import test from 'node:test';
import { helpers, proposal } from './rollbackTestSupport.mjs';

test('history is ordered by newest recorded activity with a deterministic ID tie-break', () => {
  const old = proposal('verified', 'b');
  const newer = { ...proposal('rolled_back', 'c'), history: [...old.history, { to: 'rolled_back', at: '2026-11-05T10:00:00Z' }] };
  const tie = { ...old, id: 'a' };
  const invalid = { ...old, id: 'unknown', history: [], created_at: 'invalid', decided_at: null };
  assert.deepEqual([old, newer, tie, invalid].sort(helpers.newestProposalFirst).map((p) => p.id), ['c', 'a', 'b', 'unknown']);
});

test('search includes proposal ID, titles, machine name/ID, decision actor and history actors', () => {
  const p = proposal();
  for (const query of ['OLD-CHANGE', 'remote root', 'web SERVER', 'host-id', 'approver', 'requester', 'operator', 'web operator']) assert.ok(helpers.matchesProposalSearch(p, query), query);
  assert.equal(helpers.matchesProposalSearch(p, 'unknown machine'), false);
});

test('date limits are inclusive and use the last activity rather than creation', () => {
  const p = { ...proposal(), history: [{ at: '2026-11-01T12:00:00' }] };
  assert.ok(helpers.matchesProposalDates(p, '2026-11-01', '2026-11-01'));
  assert.equal(helpers.matchesProposalDates(p, '', '2026-10-31'), false);
  assert.equal(helpers.matchesProposalDates(p, '2026-11-02', ''), false);
  assert.equal(helpers.matchesProposalDates(p, '2026-11-02', '2026-10-31'), false);
  assert.ok(helpers.matchesProposalDates(p, '', ''));
});

test('audit proposal links encode IDs and do not turn arbitrary subjects into proposals', () => {
  const id = 'proposal/one ?#&<script>';
  const href = helpers.proposalHref(id);
  const parsed = new URL(href, 'https://fixture.invalid');
  assert.equal(parsed.pathname, '/');
  assert.equal(parsed.searchParams.get('proposal'), id);
  assert.equal([...parsed.searchParams].length, 1);
  assert.equal(helpers.auditProposalId({ action: 'proposal.verified', subject: id, details: {} }), id);
  assert.equal(helpers.auditProposalId({ action: 'remediation.rollback', subject: id, details: {} }), id);
  assert.equal(helpers.auditProposalId({ action: 'action.blocked', subject: 'host', details: { proposal_id: id } }), id);
  assert.equal(helpers.auditProposalId({ action: 'target.updated', subject: 'host', details: {} }), null);
});

test('failed proposals do not become rollback eligible merely because a snapshot reference exists', () => {
  for (const state of ['proposed', 'approved', 'applying', 'failed', 'rolled_back', 'denied', 'cancelled']) assert.equal(helpers.canRequestRollback(proposal(state)), false, state);
  for (const state of ['applied', 'verified']) assert.equal(helpers.canRequestRollback(proposal(state)), true, state);
});
