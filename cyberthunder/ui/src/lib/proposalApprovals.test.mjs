import assert from 'node:assert/strict';
import test from 'node:test';
import { approvalFixture, personProposal, personVote, principal, protectedProposal, session, vote } from './approvalTestSupport.mjs';
import { proposal } from './rollbackTestSupport.mjs';

test('HTTP success and a complete count never substitute for the server state', () => {
  const { approvalProgress, approvalResult } = approvalFixture();
  const before = protectedProposal();
  const partial = { ...before, approvals: [vote()] };
  assert.deepEqual(approvalProgress(partial), { protected: true, required: 2, collected: 1, remaining: 1, mode: 'verified', basis: 'account' });
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

test('v2 counts recorded mapped people and excludes proposer aliases without merging accounts', () => {
  const p = personProposal({ approvals: [personVote(), personVote('admin-alias', 'reviewer-1'),
    personVote('proposer-alias', 'proposer'), personVote('reviewer-2')] });
  const h = approvalFixture(session('new-reviewer'));
  assert.equal(h.approvalProgress(p).basis, 'person');
  assert.equal(h.approvalProgress(p).collected, 2);
  assert.equal(h.approvalProgress(p).required, 2);
  const partial = personProposal({ approvals: [personVote()] });
  // There is no current-user mapping. Even a recorded alias cannot identify this login's person.
  const alias = session('admin-alias');
  alias.principal.name = partial.approvals[0].principal.name;
  assert.equal(approvalFixture(alias).approvalBlockReason(partial), null);
  assert.match(approvalFixture(session()).approvalBlockReason(partial), /different mapped person/);
  assert.match(approvalFixture(session('proposer')).approvalBlockReason(partial), /Another mapped person/);
});

test('v2 never counts legacy or mismatched associations as mapped-person receipts', () => {
  const wrongSource = personVote('reviewer-2');
  wrongSource.person_association.source.revision = 2;
  const wrongAccount = personVote('reviewer-3');
  wrongAccount.person_association.subject = 'reviewer-1';
  const workload = personVote('workload');
  workload.principal.kind = 'workload';
  const p = personProposal({ approvals: [personVote(), vote('legacy'), wrongSource, wrongAccount, workload] });
  assert.equal(approvalFixture().approvalProgress(p).collected, 1);
  delete p.approval_requirements.proposer_association;
  assert.equal(approvalFixture().approvalProgress(p).required, null);
  assert.match(approvalFixture(session()).approvalBlockReason(p), /requirements are unavailable/);
  assert.doesNotMatch(approvalFixture(session()).approvalBlockReason(p), /legacy/);
});

test('unknown schema and source modes cannot be displayed as a valid quorum', () => {
  for (const change of [r => { r.version = 3; }, r => { r.identity_basis.revision = 0; },
    r => { r.identity_basis.policy_sha256 = ['a'.repeat(64)]; },
    r => { r.identity_basis.policy_sha256 = 'not-a-hash'; }, r => { r.mode = 'unverified_dev'; }]) {
    const p = personProposal({ approvals: [personVote()] });
    change(p.approval_requirements);
    assert.equal(approvalFixture().approvalProgress(p).required, null);
    assert.equal(approvalFixture().approvalProgress(p).collected, 0);
  }
});
