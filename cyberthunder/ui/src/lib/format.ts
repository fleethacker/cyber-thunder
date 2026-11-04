import dayjs from 'dayjs';
import relativeTime from 'dayjs/plugin/relativeTime';
import type { Severity } from '../api/types';

dayjs.extend(relativeTime);

export function fmtTime(ts?: string | null): string {
  if (!ts) return '-';
  const d = dayjs(ts);
  return d.isValid() ? d.format('YYYY-MM-DD HH:mm:ss') : ts;
}

export function fmtClock(ts?: string | null): string {
  if (!ts) return '-';
  const d = dayjs(ts);
  return d.isValid() ? d.format('HH:mm:ss') : ts;
}

export function fmtAgo(ts?: string | null): string {
  if (!ts) return '-';
  const d = dayjs(ts);
  return d.isValid() ? d.fromNow() : ts;
}

export function ageSeconds(ts?: string | null): number {
  if (!ts) return 0;
  const d = dayjs(ts);
  return d.isValid() ? dayjs().diff(d, 'second') : 0;
}

export function fmtBytes(n?: number | null): string {
  if (n === undefined || n === null || Number.isNaN(n)) return '-';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

export function fmtSeconds(s?: number | null): string {
  if (s === undefined || s === null || Number.isNaN(s)) return '-';
  if (s < 1) return `${(s * 1000).toFixed(0)} ms`;
  if (s < 120) return `${s.toFixed(1)} s`;
  if (s < 7200) return `${(s / 60).toFixed(1)} min`;
  return `${(s / 3600).toFixed(1)} h`;
}

export function short(hash?: string | null, n = 8): string {
  return hash ? hash.slice(0, n) : '-';
}

export const SEVERITY_ORDER: Severity[] = ['high', 'medium', 'low', 'info', 'unknown'];

export function severityRank(s?: string | null): number {
  return { high: 3, medium: 2, low: 1, info: 0, unknown: 0 }[s ?? 'unknown'] ?? 0;
}

/** CAT I red, CAT II amber, CAT III blue, info grey (docs/UI.md "Visual language"). */
export function severityColor(s?: string | null): string {
  switch (s) {
    case 'high': return 'red';
    case 'medium': return 'orange';
    case 'low': return 'blue';
    default: return 'gray';
  }
}

export function catLabel(s?: string | null): string {
  switch (s) {
    case 'high': return 'CAT I';
    case 'medium': return 'CAT II';
    case 'low': return 'CAT III';
    case 'info': return 'INFO';
    default: return '-';
  }
}

export function stateColor(state?: string | null): string {
  switch (state) {
    case 'proposed': return 'gray';
    case 'approved': return 'teal';
    case 'applying': return 'yellow';
    case 'applied': return 'cyan';
    case 'verified': return 'green';
    case 'failed': return 'red';
    case 'rolled_back': return 'violet';
    case 'denied': return 'dark';
    case 'cancelled': return 'dark';
    default: return 'gray';
  }
}

export function statusColor(status?: string | null): string {
  switch (status) {
    case 'open': return 'red';
    case 'not_a_finding': return 'green';
    case 'not_applicable': return 'gray';
    case 'not_reviewed': return 'yellow';
    case 'error': return 'grape';
    default: return 'gray';
  }
}

export function label(s?: string | null): string {
  return (s ?? '-').replace(/_/g, ' ');
}

/** Public reference link for a cited identifier. Plain anchors: offline they simply do not resolve. */
export function citationHref(id: string): string | null {
  if (/^CVE-\d{4}-\d+$/.test(id)) return `https://nvd.nist.gov/vuln/detail/${id}`;
  if (/^T\d{4}(\.\d{3})?$/.test(id)) return `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`;
  if (/^[A-Z][A-Z0-9]{1,15}-\d{2}-\d{6}$/.test(id) || /^V-\d+$/.test(id) || /^SV-\d+r\d+_rule$/.test(id))
    return `https://public.cyber.mil/stigs/srg-stig-tools/?q=${encodeURIComponent(id)}`;
  return null;
}

export function citationKind(id: string): string {
  if (/^CVE-/.test(id)) return 'CVE';
  if (/^CCI-/.test(id)) return 'CCI';
  if (/^CCE-/.test(id)) return 'CCE';
  if (/^T\d{4}/.test(id)) return 'ATT&CK';
  if (/^\d{4}-[AB]-\d{4}$/.test(id)) return 'IAVM';
  if (/^V-\d+$/.test(id)) return 'Group';
  if (/^SV-/.test(id)) return 'Rule';
  if (/^[A-Z][A-Z0-9]{1,15}-\d{2}-\d{6}$/.test(id)) return 'STIG';
  return 'Ref';
}
