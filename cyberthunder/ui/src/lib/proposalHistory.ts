import type { AuditRecord, ProposalPlus, ProposalState } from '../api/types';

export const QUEUE_STATES: ProposalState[] = ['proposed', 'approved', 'applying'];
export const HISTORY_STATES: ProposalState[] = [...QUEUE_STATES, 'applied', 'verified', 'failed', 'rolled_back', 'denied', 'cancelled'];

/** A snapshot reference alone does not establish recoverability of a failed change. */
export function canRequestRollback(p: ProposalPlus): boolean {
  return p.state === 'applied' || p.state === 'verified';
}

export function proposalChangedAt(p: ProposalPlus): string {
  const times = [p.created_at, p.decided_at, ...p.history.flatMap((h) => [h.at, h.ts])];
  return times.filter((value): value is string => typeof value === 'string' && Number.isFinite(Date.parse(value)))
    .sort((a, b) => Date.parse(b) - Date.parse(a))[0] ?? '';
}

export function newestProposalFirst(a: ProposalPlus, b: ProposalPlus): number {
  const time = (p: ProposalPlus) => Date.parse(proposalChangedAt(p)) || 0;
  return time(b) - time(a) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
}

export function matchesProposalSearch(p: ProposalPlus, search: string): boolean {
  const terms = search.trim().toLowerCase().split(/\s+/).filter(Boolean);
  const haystack = [p.id, p.title, p.finding?.title, p.host, p.target?.name, p.decided_by, ...p.history.map((h) => h.actor)].filter(Boolean).join(' ').toLowerCase();
  return terms.every((term) => haystack.includes(term));
}

/** Inclusive browser-local dates of the last recorded activity. */
export function matchesProposalDates(p: ProposalPlus, from: string, through: string): boolean {
  if (!from && !through) return true;
  const at = proposalChangedAt(p);
  if (!at) return false;
  const d = new Date(at);
  const day = [d.getFullYear(), String(d.getMonth() + 1).padStart(2, '0'), String(d.getDate()).padStart(2, '0')].join('-');
  return (!from || day >= from) && (!through || day <= through);
}

export function proposalHref(id: string): string {
  // Router-relative destination; HashRouter produces #/?proposal=... in the app.
  return `/?${new URLSearchParams({ proposal: id })}`;
}

export function auditProposalId(record: AuditRecord): string | null {
  if ((record.action.startsWith('proposal.') || record.action.startsWith('remediation.')) && record.subject) return record.subject;
  const id = (record.details as { proposal_id?: unknown } | null)?.proposal_id;
  return typeof id === 'string' && id.trim() ? id : null;
}
