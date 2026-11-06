import { createModuleLoader } from './moduleTestSupport.mjs';
import { proposal } from './rollbackTestSupport.mjs';

// The public session uses issuer/subject/source; saved principal evidence uses iss/sub/via.
export const principal = (subject, changes = {}) => ({ iss: 'https://identity.example', sub: subject,
  name: `Reviewer ${subject}`, kind: 'human', via: 'oidc', verified: true, roles: ['approver'], ...changes });
export const session = (subject = 'reviewer-1', changes = {}) => ({ mode: 'oidc', authenticated: true,
  login_available: true, permissions: ['read', 'approve', 'plan'],
  principal: { issuer: 'https://identity.example', subject, source: 'oidc', name: `Reviewer ${subject}`,
    actor: `human:${subject}`, roles: ['approver'], verified: true }, ...changes });
export const vote = (subject = 'reviewer-1', changes = {}) => ({ id: `vote-${subject}`, actor: `human:${subject}`,
  principal: principal(subject), approved_at: '2026-11-05T16:00:00Z', note: 'Reviewed the proposed change',
  requirements_sha256: 'requirements-digest', payload_sha256: 'payload-digest', assessment_sha256: 'assessment-digest',
  assessment: { status: 'reviewed', id: 'shared-receipt', note: 'Checked management access and recovery.' }, ...changes });
export const protectedProposal = (changes = {}) => ({ ...proposal('proposed', 'change'),
  proposed_by: 'human:proposer', proposed_principal: principal('proposer'), required_approvals: 2,
  approval_requirements: { version: 1, ruleset: 'cat-i-two-person-v1', mode: 'verified', required_approvals: 2,
    payload_sha256: 'payload-digest', source: { severity: 'high', finding_id: 'finding',
      finding_sha256: 'finding-digest', fix_sha256: 'fix-digest' } }, approvals: [], ...changes });

export const personBasis = () => ({ mode: 'person', policy_version: 2, version: 1,
  namespace: 'operators', revision: 1, policy_sha256: 'a'.repeat(64) });
export const association = (subject, id = subject) => ({ issuer: principal(subject).iss, subject,
  person_id: id, source: personBasis() });
export const personVote = (subject = 'reviewer-1', id = subject) => vote(subject, { person_association: association(subject, id) });
export const personProposal = (changes = {}) => {
  const p = protectedProposal();
  Object.assign(p.approval_requirements, { version: 2, ruleset: 'cat-i-person-association-v1',
    identity_basis: personBasis(), proposer_association: association('proposer') });
  return { ...p, ...changes };
};

export function approvalFixture(identity = null) {
  const load = createModuleLoader();
  load(new URL('../api/identity.ts', import.meta.url)).setSessionIdentity(identity);
  return load(new URL('./proposalApprovals.ts', import.meta.url));
}
