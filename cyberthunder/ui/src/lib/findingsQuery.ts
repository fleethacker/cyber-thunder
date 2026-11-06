import type { FindingSort } from '../api/types';
import { sessionIdentity } from '../api/identity';
import { useLocalPref } from './hooks';

export const REASSESSMENT_LABELS: Record<string, string> = {
  not_reassessed: 'Not reassessed', no_known_gap: 'No known gap', unknown: 'Unknown',
};
export const FINDING_SORTS: { value: FindingSort; label: string }[] = [
  { value: 'default', label: 'Default priority' }, { value: 'severity', label: 'Severity' },
  { value: 'host', label: 'Machine' }, { value: 'asset_type', label: 'Asset type' },
  { value: 'category', label: 'Category' }, { value: 'title', label: 'Title' },
  { value: 'rule_id', label: 'Rule ID' }, { value: 'rule_version', label: 'STIG ID / rule version' }, { value: 'source', label: 'Source' },
  { value: 'observed_at', label: 'Observation time' }, { value: 'collected_at', label: 'Collection time' },
  { value: 'benchmark', label: 'Benchmark' }, { value: 'benchmark_release', label: 'Release' },
  { value: 'confidence', label: 'Evidence confidence' }, { value: 'review', label: 'Human review' },
];

/** Keep existing dev preferences; authenticated accounts never inherit another viewer's filters. */
export function useFindingsPref<T>(key: string, initial: T): [T, (value: T) => void] {
  const identity = sessionIdentity();
  const p = identity?.principal;
  const storageKey = !identity || identity.mode === 'dev' ? key
    : `${key}:${JSON.stringify([identity.mode, p?.issuer, p?.subject, p?.actor])}`;
  const [stored, set] = useLocalPref<unknown>(storageKey, initial);
  const valid = (value: unknown): value is T => {
    if (Array.isArray(initial)) {
      return Array.isArray(value) && value.length <= 1000
        && value.every((v) => typeof v === 'string' && v.length > 0 && v.length <= 4096
          && (key !== 'ct.f.reassessment' || Object.prototype.hasOwnProperty.call(REASSESSMENT_LABELS, v)));
    }
    if (key === 'ct.f.sort') return FINDING_SORTS.some((s) => s.value === value);
    if (key === 'ct.f.direction') return value === 'asc' || value === 'desc';
    return typeof value === 'string';
  };
  return [valid(stored) ? stored : initial, (value) => set(valid(value) ? value : initial)];
}
