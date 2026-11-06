import type { ConfidenceGrade, FindingReview, FindingReviewInput, ReviewDisposition } from '../api/types';

export const CONFIDENCE_LABELS: Record<ConfidenceGrade, string> = { high: 'High', medium: 'Medium', low: 'Low', unknown: 'Unknown' };
export const REVIEW_LABELS: Record<ReviewDisposition, string> = {
  unreviewed: 'Unreviewed', confirmed: 'Confirmed', false_positive: 'False positive',
  not_applicable: 'Not applicable', needs_investigation: 'Needs investigation',
  risk_accepted: 'Risk accepted', risk_revoked: 'Risk acceptance revoked',
};
export const REVIEW_FILTER_LABELS: Record<string, string> = { ...REVIEW_LABELS,
  risk_expired: 'Risk acceptance expired', risk_reopened: 'Risk acceptance reopened' };

export const isSuppressed = (review?: FindingReview | null) => !!(review?.active && review.suppressed);
export const isRemediationHeld = (review?: FindingReview | null) => !!(review?.active && review.remediation_held);
export const reviewDisposition = (review?: FindingReview | null): ReviewDisposition => review?.active ? review.disposition : 'unreviewed';
export const needsExpiry = (disposition: ReviewDisposition) => ['false_positive', 'not_applicable', 'risk_accepted'].includes(disposition);

export interface ReviewDraft { disposition: ReviewDisposition; reason: string; supportingEvidence: string; expiresAt: string }

export function reviewDraft(review?: FindingReview | null): ReviewDraft {
  const current = review?.active ? review.current : null;
  const expiry = current?.expires_at ? new Date(current.expires_at) : null;
  return {
    disposition: reviewDisposition(review), reason: current?.reason ?? '', supportingEvidence: current?.supporting_evidence ?? '',
    expiresAt: expiry && !Number.isNaN(expiry.getTime())
      ? new Date(expiry.getTime() - expiry.getTimezoneOffset() * 60000).toISOString().slice(0, 16) : '',
  };
}

export function reviewInput(draft: ReviewDraft, review: FindingReview, now = Date.now()): FindingReviewInput {
  if (!draft.reason.trim()) throw new Error('Add a reason for this review, including a return to Unreviewed.');
  const expiry = draft.expiresAt && draft.disposition !== 'risk_revoked' ? new Date(draft.expiresAt).getTime() : null;
  if (needsExpiry(draft.disposition) && expiry === null) throw new Error('Set a future expiry for this decision.');
  if (expiry !== null && (!Number.isFinite(expiry) || expiry <= now)) throw new Error('Expiry must be a valid future date and time.');
  if (draft.disposition === 'risk_accepted') {
    if (!draft.supportingEvidence.trim()) throw new Error('Supporting evidence is required to accept risk.');
    if (expiry !== null && expiry > now + 30 * 86400000) throw new Error('Risk acceptance expiry must be within 30 days.');
  }
  if (!review.evidence_fingerprint || !Number.isInteger(review.revision) || review.revision < 0) throw new Error('Refresh the current evidence before saving a review.');
  return {
    disposition: draft.disposition, reason: draft.reason.trim(), supporting_evidence: draft.supportingEvidence.trim(),
    expires_at: expiry === null ? null : new Date(expiry).toISOString(),
    expected_revision: review.revision, evidence_fingerprint: review.evidence_fingerprint,
  };
}
