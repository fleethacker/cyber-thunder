import { request } from './client';
import type { ScanRun, TargetScanResult } from './types';

export interface ScanCoverage {
  version: number;
  target_id: string;
  asset_type: string;
  simulated: boolean;
  phase: 'preflight' | 'observed';
  complete: boolean;
  applicability: { status: string; unknown: string | null; observed_at: string | null; age_seconds: number | null };
  products: { product_key: string; library_url: string; manual: { status: string; count: number }; scap: { status: string; count: number } }[];
  native: { status: string; requires_download: boolean };
  scanner: { engine: string | null; location: string | null; status: string; content_status: string; applicability: string;
    observed_at: string | null; age_seconds: number | null; stale: boolean };
  warnings: string[];
  actions: { label: string; href: string }[];
}
export interface ScanPreflight {
  version: number;
  generated_at: string;
  local_only: true;
  automatic_downloads: false;
  modules: string[];
  targets: ScanCoverage[];
}
export type ScanRunWithCoverage = Omit<ScanRun, 'results'> & {
  coverage_incomplete?: boolean | null;
  results: Record<string, TargetScanResult & { coverage?: ScanCoverage | null }>;
};

export function scanPreflight(targetIds: string[], modules: string[]): Promise<ScanPreflight> {
  const query = new URLSearchParams();
  targetIds.forEach((id) => query.append('target_ids', id));
  modules.forEach((module) => query.append('modules', module));
  return request<ScanPreflight>('GET', `/scans/preflight?${query.toString()}`);
}
