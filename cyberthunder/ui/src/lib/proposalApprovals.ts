import { sessionIdentity, type SessionIdentity } from '../api/identity';
import type { PersonAssociation, PersonIdentityBasis, Proposal, RecordedPrincipalEvidence } from '../api/types';

const key = (issuer?: string, subject?: string) => issuer && subject ? JSON.stringify([issuer, subject]) : null;
const recordedKey = (evidence?: RecordedPrincipalEvidence | null) => key(evidence?.iss, evidence?.sub);
const opaque = (value?: string) => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
const validBasis = (b?: PersonIdentityBasis) => b?.mode === 'person' && b.policy_version === 2 && b.version === 1
  && opaque(b.namespace) && Number.isSafeInteger(b.revision) && b.revision > 0
  && typeof b.policy_sha256 === 'string' && /^[0-9a-f]{64}$/.test(b.policy_sha256);
function mappedKey(e: RecordedPrincipalEvidence | null | undefined, a?: PersonAssociation, b?: PersonIdentityBasis) {
  if (!validBasis(b) || !validBasis(a?.source) || !opaque(a?.person_id)
      || !e || e.verified !== true || e.kind !== 'human' || !['oidc', 'mesh'].includes(e.via)
      || key(a?.issuer, a?.subject) !== recordedKey(e)
      || a?.source.namespace !== b?.namespace || a?.source.revision !== b?.revision
      || a?.source.policy_sha256 !== b?.policy_sha256) return null;
  return key(b?.namespace, a?.person_id);
}

/** Presentation of server records only; neither counts nor browser checks authorize a change. */
export function approvalProgress(p: Proposal) {
  const protectedRecord = p.approval_requirements != null || p.required_approvals != null || !!p.approvals?.length;
  const mode = p.approval_requirements?.mode;
  const r = p.approval_requirements;
  const basis = r?.version === 2 && r.ruleset === 'cat-i-person-association-v1' && mode === 'verified'
    && validBasis(r.identity_basis) ? 'person'
    : r?.version === 1 && r.ruleset === 'cat-i-two-person-v1' && !r.identity_basis && !r.proposer_association
      ? mode === 'unverified_dev' ? 'local' : mode === 'verified' ? 'account' : 'unavailable' : 'unavailable';
  const proposer = basis === 'person' ? mappedKey(p.proposed_principal, r?.proposer_association, r?.identity_basis)
    : recordedKey(p.proposed_principal);
  const required = basis !== 'unavailable' && proposer && Number.isInteger(p.required_approvals) && p.required_approvals! > 0
    && p.required_approvals === p.approval_requirements?.required_approvals ? p.required_approvals! : null;
  const people = new Set<string>();
  for (const vote of p.approvals ?? []) {
    const e = vote.principal, person = basis === 'person' ? mappedKey(e, vote.person_association, r?.identity_basis)
      : vote.person_association ? null : recordedKey(e);
    const qualified = mode === 'verified' ? e?.verified === true && e.kind === 'human' && ['oidc', 'mesh'].includes(e.via)
      : mode === 'unverified_dev' && e?.verified === false && e.via === 'dev';
    if (required && qualified && person && person !== proposer && !vote.actor?.startsWith('policy:')) people.add(person);
  }
  return { protected: protectedRecord, required, collected: people.size,
    remaining: required === null ? null : Math.max(0, required - people.size), mode, basis };
}

export function approvalBlockReason(p: Proposal, actor = '', identity: SessionIdentity | null = sessionIdentity()): string | null {
  if (p.state !== 'proposed') return 'This proposal is not awaiting approval.';
  const progress = approvalProgress(p);
  if (!progress.protected) return identity && identity.mode !== 'dev'
    ? 'This legacy proposal has no verified approval requirements. Cancel it and create a new proposal.' : null;
  if (!progress.required || !['verified', 'unverified_dev'].includes(progress.mode ?? '')) {
    return 'Approval requirements are unavailable. Refresh the proposal before deciding.';
  }
  let person: string | null;
  if (progress.mode === 'verified') {
    const current = identity?.principal;
    if (!identity?.authenticated || identity.mode === 'dev' || current?.verified !== true
        || current.source !== identity.mode || !(person = key(current.issuer, current.subject))) {
      return 'Verified reviewer identity is unavailable. Refresh sign-in before approving.';
    }
  } else {
    if (identity && identity.mode !== 'dev') return 'An unverified development proposal cannot become a verified approval. Create a new proposal.';
    person = key('local-development', actor.trim().toLowerCase());
  }
  const reviewer = progress.basis === 'person' ? 'mapped person' : 'account';
  if (person && person === recordedKey(p.proposed_principal)) return `You proposed this change. Another ${reviewer} must approve it.`;
  if (person && p.approvals?.some(vote => recordedKey(vote.principal) === person)) {
    return `Your approval is already recorded. A different ${reviewer} must provide any remaining approval.`;
  }
  if (progress.remaining === 0) return 'The recorded count is complete, but the server still reports proposed. Refresh before deciding.';
  return null;
}

export const fixedApprovalAssessment = (p: Proposal) => approvalProgress(p).protected && !!p.approvals?.length;
export const approvalReceiptOnly = (p: Proposal) => approvalProgress(p).protected && p.state === 'approved';

export function approvalResult(before: Proposal, after: Proposal) {
  const progress = approvalProgress(after);
  if (before.id !== after.id) return { recorded: false, approved: false, message: 'The response did not confirm this proposal. Refresh its state.' };
  if (after.state === 'approved') return { recorded: true, approved: true, message: 'The server marked this proposal approved.' };
  const recorded = after.state === 'proposed' && progress.collected > approvalProgress(before).collected;
  return { recorded, approved: false, message: recorded
    ? `Approval recorded: ${progress.collected} of ${progress.required ?? '?'}; ${progress.remaining ?? '?'} remaining. The proposal is still proposed.`
    : `The server reports ${after.state.replace(/_/g, ' ')}. No additional approval was confirmed; refresh before retrying.` };
}
