import type { LinkState } from '../api/types';

export function linkLabel(link?: Partial<LinkState> | null): string {
  if (link?.offline_override) return 'Operator offline';
  if (link?.mode === 'test') return link.test_connected ? 'TEST: connected' : 'TEST: disconnected';
  if (link?.reachability === 'reachable') return 'Endpoint observed reachable';
  if (link?.reachability === 'unreachable') return 'Endpoint observed unreachable';
  return 'Reachability unknown';
}

export function rateLabel(link?: Partial<LinkState> | null): string {
  if (link?.mode === 'test') return 'TEST estimate: ' + link.kbps + ' kbps / ' + link.latency_ms + ' ms configured delay';
  return link?.observed_kbps == null ? 'Observed application rate unknown'
    : 'Observed application rate: ' + link.observed_kbps + ' kbps';
}
