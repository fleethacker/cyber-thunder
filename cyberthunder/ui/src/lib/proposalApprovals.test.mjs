import assert from 'node:assert/strict';
import test from 'node:test';
import { approvalFixture, principal, protectedProposal, session, vote } from './approvalTestSupport.mjs';
import { proposal } from './rollbackTestSupport.mjs';

test('HTTP success and a complete count never substitute for the server state', () => {
  const { approvalProgress, approvalResult } = approvalFixture();
  const before = protectedProposal();
  const partial = { ...before, approvals: [vote()] };
  assert.deepEqual(approvalProgress(partial), { protected: true, required: 2, collected: 1, remaining: 1, mode: 'verified' });
  assert.equal(approvalResult(before, partial).approved, false);
  assert.equal(approvalResult(before, partial).recorded, true);
  assert.match(approvalResult(before, partial).message, /1 of 2; 1 remaining.*still proposed/);
  assert.equal(approvalResult(before, before).recorded, false);
  const complete = { ...partial, approvals: [vote(), vote('reviewer-2')] };
  assert.equal(approvalProgress(complete).remaining, 0);
  assert.equal(approvalResult(partial, complete).approved, false);
  assert.equal(approvalResult(partial, { ...complete, state: 'approved' }).approved, true);
  assert.equal(approvalResult(partial, { ...complete, id: 'different', state: 'approved' }).approved, false);
});

test('counts distinct issuer and subject pairs, excluding proposer, workloads and policies', () => {
  const p = protectedProposal({ approvals: [vote(), vote('renamed', { principal: principal('reviewer-1', { name: 'New name' }) }),
    vote('proposer'), vote('workload', { principal: principal('workload', { kind: 'workload' }) }),
    vote('policy', { actor: 'policy:standing-rule' }), vote('unverified', { principal: principal('unverified', { verified: false }) }),
    vote('reviewer-1', { principal: principal('reviewer-1', { iss: 'https://other.example' }) })] });
  assert.equal(approvalFixture().approvalProgress(p).collected, 2);
});

test('proposer and duplicate hints use stable identities, never display names or typed actor', () => {
  const p = protectedProposal({ approvals: [vote()] });
  assert.match(approvalFixture(session('proposer')).approvalBlockReason(p, 'Somebody else'), /You proposed/);
  assert.match(approvalFixture(session()).approvalBlockReason(p, 'Somebody else'), /already recorded/);
  const different = session('reviewer-2');
  different.principal.name = p.proposed_principal.name;
  assert.equal(approvalFixture(different).approvalBlockReason(p, 'human:proposer'), null);
  different.principal.subject = 'reviewer-1';
  different.principal.issuer = 'https://other.example';
  assert.equal(approvalFixture(different).approvalBlockReason(p), null);
});

test('verified identity and requirement gaps block the hint without inventing authority', () => {
  const p = protectedProposal();
  assert.match(approvalFixture().approvalBlockReason(p), /identity is unavailable/);
  assert.match(approvalFixture(session()).approvalBlockReason({ ...p, required_approvals: 1 }), /requirements are unavailable/);
  assert.match(approvalFixture(session()).approvalBlockReason(proposal('proposed', 'legacy')), /legacy proposal/);
  assert.match(approvalFixture(session()).approvalBlockReason({ ...p, approvals: [vote(), vote('reviewer-2')] }), /already recorded/);
  assert.match(approvalFixture(session('reviewer-3')).approvalBlockReason({ ...p, approvals: [vote(), vote('reviewer-2')] }), /server still reports proposed/);
});

test('one protected approval and default local single approval both follow returned state', () => {
  const h = approvalFixture(session());
  const p = protectedProposal();
  p.required_approvals = p.approval_requirements.required_approvals = 1;
  const after = { ...p, state: 'approved', approvals: [vote()] };
  assert.equal(h.approvalProgress(after).remaining, 0);
  assert.equal(h.approvalResult(p, after).approved, true);
  const legacy = proposal('proposed', 'local');
  assert.equal(approvalFixture().approvalBlockReason(legacy, 'Local Operator'), null);
  assert.equal(h.approvalProgress(legacy).protected, false);
  assert.equal(h.approvalResult(legacy, { ...legacy, state: 'approved' }).approved, true);
});

test('explicit unverified rules retain their development identity and cannot become verified', () => {
  const local = name => principal(name.toLowerCase(), { iss: 'local-development', name, verified: false, kind: 'dev', via: 'dev' });
  const p = protectedProposal({ proposed_principal: local('Proposer'), approvals: [vote('local', { principal: local('Reviewer') })] });
  p.approval_requirements.mode = 'unverified_dev';
  assert.equal(approvalFixture().approvalProgress(p).collected, 1);
  assert.match(approvalFixture().approvalBlockReason(p, ' REVIEWER '), /already recorded/);
  assert.match(approvalFixture().approvalBlockReason(p, 'PROPOSER'), /You proposed/);
  assert.match(approvalFixture(session()).approvalBlockReason(p), /unverified development proposal/);
});
