import { sessionIdentity, type SessionIdentity } from '../api/identity';
import type { Proposal, RecordedPrincipalEvidence } from '../api/types';

const key = (issuer?: string, subject?: string) => issuer && subject ? JSON.stringify([issuer, subject]) : null;
const recordedKey = (evidence?: RecordedPrincipalEvidence | null) => key(evidence?.iss, evidence?.sub);

/** Presentation of server records only; neither counts nor browser checks authorize a change. */
export function approvalProgress(p: Proposal) {
  const protectedRecord = p.approval_requirements != null || p.required_approvals != null || !!p.approvals?.length;
  const mode = p.approval_requirements?.mode;
  const required = Number.isInteger(p.required_approvals) && p.required_approvals! > 0
    && p.required_approvals === p.approval_requirements?.required_approvals ? p.required_approvals! : null;
  const people = new Set<string>();
  for (const vote of p.approvals ?? []) {
    const e = vote.principal, person = recordedKey(e);
    const qualified = mode === 'verified' ? e?.verified === true && e.kind === 'human' && ['oidc', 'mesh'].includes(e.via)
      : mode === 'unverified_dev' && e?.verified === false && e.via === 'dev';
    if (qualified && person && person !== recordedKey(p.proposed_principal) && !vote.actor?.startsWith('policy:')) people.add(person);
  }
  return { protected: protectedRecord, required, collected: people.size,
    remaining: required === null ? null : Math.max(0, required - people.size), mode };
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
  if (person && person === recordedKey(p.proposed_principal)) return 'You proposed this change. Another person must approve it.';
  if (person && p.approvals?.some(vote => recordedKey(vote.principal) === person)) {
    return 'Your approval is already recorded. A different person must provide any remaining approval.';
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
