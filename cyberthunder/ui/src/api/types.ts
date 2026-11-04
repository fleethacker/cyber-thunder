// Mirrors docs/API.md. Keep field names identical to the Python to_dict() output.

export type Severity = 'high' | 'medium' | 'low' | 'info' | 'unknown';
export type FindingStatus = 'open' | 'not_a_finding' | 'not_applicable' | 'not_reviewed' | 'error';
export type AssetType = 'linux' | 'windows' | 'cisco_ios' | 'kubernetes' | 'containers';
export const ASSET_TYPES: AssetType[] = ['linux', 'windows', 'cisco_ios', 'kubernetes', 'containers'];
export const TRANSPORTS = ['ssh', 'winrm', 'local', 'fixture', 'simulated', 'file', 'kubeconfig'] as const;
export type ProposalState =
  | 'proposed' | 'approved' | 'denied' | 'cancelled' | 'applying'
  | 'applied' | 'verified' | 'failed' | 'rolled_back';

export interface Reference { system: string; id: string }

export interface Explanation {
  finding_id: string;
  risk: string;
  impact: string;
  plan: string;
  citations: string[];
  backend: string;
  model: string | null;
  generated_at: string;
  validated: boolean;
  dropped_citations: string[];
  fallback: boolean;
  latency_s: number | null;
  attempts: number;
}

export interface FixEntry {
  fix_ref: string;
  title: string;
  asset_type: string;
  applies_to: string[];
  kind: 'script' | 'powershell' | 'config_snippet' | 'manifest' | 'runbook';
  payload: string;
  steps: string[];
  disruption: 'low' | 'medium' | 'high';
  reboot: boolean;
  restarts_services: string[];
  reversible: boolean;
  rollback_kind: string;
  rollback_steps: string[];
  before_state: Record<string, unknown>;
  verify: Record<string, unknown>;
  citations: string[];
  source: string;
  patch: boolean;
  notes: string;
  preview: string;
  rollback_plan: string;
  risk_tags: string[];
}

export interface Finding {
  id: string;
  host: string;
  source: string;
  rule_id: string;
  title: string;
  severity: Severity;
  status: FindingStatus;
  rule_version: string | null;
  group_id: string | null;
  benchmark: string | null;
  benchmark_release: string | null;
  description: string;
  check_text: string | null;
  fix_text: string | null;
  fix_script: string | null;
  fix_ansible: string | null;
  references: Reference[];
  evidence: string | null;
  collected_at: string;
  raw_ref: string | null;
  tags: string[];
  asset_type: string | null;
  fix_ref: string | null;
  scan_id: string | null;
}

export interface FindingPlus extends Finding {
  cat: string;
  explanation: Explanation | null;
  fix: FixEntry | null;
  proposal?: { id: string; state: ProposalState } | null;
}

export interface FindingsSummary {
  total: number;
  hosts: string[];
  open_by_severity: Partial<Record<Severity, number>>;
  by_status: Partial<Record<FindingStatus, number>>;
  /** distinct finding sources in the scan, when the server reports them */
  sources?: string[];
}

export interface FindingsPage {
  findings: FindingPlus[];
  total: number;
  scan_id: string | null;
  summary: FindingsSummary | null;
}

export interface PolicyDecision { auto_eligible: boolean; rule: string | null; reasons: string[] }

/** Proposal.history entries are written by the gate; fields vary, so everything is optional. */
export interface HistoryEntry {
  from?: string;
  to?: string;
  state?: string;
  actor?: string;
  at?: string;
  ts?: string;
  note?: string | null;
  seq?: number;
  [k: string]: unknown;
}

export interface TargetBrief { id: string; name: string; asset_type: string | null; simulated: boolean; known?: boolean }

export interface Proposal {
  id: string;
  finding_id: string;
  host: string;
  title: string;
  fix_ref: string;
  fix_preview: string;
  rollback_plan: string;
  risk: string;
  citations: string[];
  state: ProposalState;
  created_at: string;
  decided_by: string | null;
  decided_at: string | null;
  decision_note: string | null;
  before_state_ref: string | null;
  history: HistoryEntry[];
}

export interface ProposalPlus extends Proposal {
  fix: FixEntry | null;
  finding: FindingPlus | null;
  policy: PolicyDecision | null;
  severity: Severity;
  cat: string;
  target: TargetBrief | null;
}

/** One file the fix touched: copies taken before apply and after it, and a unified diff of the two. */
export interface DiffFile {
  path: string;
  before_excerpt: string | null;
  after_excerpt: string | null;
  diff: string | null;
}

/** GET /proposals/{id}/diff: the engine's record of what changed and how it was checked. */
export interface ProposalDiff {
  proposal?: Record<string, unknown>;
  fix?: Record<string, unknown> | null;
  before_state?: Record<string, unknown> | null;
  before: Record<string, unknown>;
  after: Record<string, unknown>;
  apply: Record<string, unknown> | null;
  verify: Record<string, unknown> | null;
  rollback?: Record<string, unknown> | null;
  files: DiffFile[];
}

export type BulkItem = { id: string; state: ProposalState } | { id: string; error: string };
export interface BulkResult { results: BulkItem[] }

export interface Target {
  id: string;
  name: string;
  asset_type: AssetType;
  transport: string;
  address: string | null;
  port: number | null;
  username: string | null;
  credential_ref: string | null;
  sudo: boolean;
  tags: string[];
  in_scope: boolean;
  simulated: boolean;
  options: Record<string, unknown>;
  last_scan: string | null;
  notes: string;
  added_at: string;
}

export type AssetFacts = Record<string, unknown>;

export interface TargetScanResult {
  target_id: string;
  status: string;
  started_at: string | null;
  finished_at: string | null;
  findings: number;
  open: number;
  errors: string[];
  facts: Record<string, unknown> | null;
}

export interface ScanRun {
  id: string;
  targets: string[];
  modules: string[];
  rule_filter: string[] | null;
  trigger: string;
  requested_by: string;
  status: string; // pending | running | done | error | skipped | cancelled
  started_at: string;
  finished_at: string | null;
  results: Record<string, TargetScanResult>;
  findings_count: number;
  summary: Partial<FindingsSummary>;
  error: string | null;
  progress: { done: number; total: number };
}

export interface ScanRequest {
  target_ids?: string[];
  modules?: string[];
  rule_filter?: string[];
  trigger?: string;
}

export interface AuditRecord {
  seq: number;
  ts: string;
  node: string;
  actor: string;
  action: string;
  subject: string | null;
  outcome: string;
  details: Record<string, unknown>;
  prev_hash: string;
  hash: string;
}

export interface AuditPage { records: AuditRecord[]; head: string; count: number }
export interface AuditVerify { ok: boolean; count: number; head: string; bad_seq: number | null; reason: string | null }

export interface KillStatus { engaged: boolean; by: string | null; reason: string | null; at: string | null; via: string | null }

export interface LinkState { kbps: number; latency_ms: number; connected: boolean }

export interface LlmStatus { backend: string; model: string | null; available: boolean; detail?: string; queue?: number }

export interface Status {
  product: string;
  version: string;
  node: string;
  kill: KillStatus;
  audit: { count: number; head: string; verified: boolean; detail: string };
  policy: { enabled: boolean; signed_by: string | null; rules: number };
  adapters: string[];
  targets: number;
  fixes: number;
  demo: boolean;
  llm: LlmStatus;
  link: LinkState;
  outbox: { pending: number };
}

export interface PolicyRule {
  name: string;
  asset_types: string[];
  max_disruption: 'low' | 'medium' | 'high';
  allow_reboot: boolean;
  allow_patch: boolean;
  allow_service_restart: boolean;
  fix_allowlist: string[];
  target_allowlist: string[];
  max_severity: 'high' | 'medium' | 'low' | null;
  window_start: string | null;
  window_end: string | null;
}

export interface AutomationPolicy {
  enabled: boolean;
  signed_by: string | null;
  signed_at: string | null;
  reason: string | null;
  rules: PolicyRule[];
  version: number;
}

export interface RuleRef { rule_id: string; stig_id: string | null; title: string; severity: string; change?: string }

export interface DeltaReport {
  id: string;
  benchmark_id: string;
  old_release: string | null;
  new_release: string | null;
  rules_added: RuleRef[];
  rules_removed: RuleRef[];
  rules_changed: RuleRef[];
  counts: Record<string, number>;
  sizes: { full_bytes: number; delta_bytes: number; compressed_bytes: number; ratio: number };
  transfer: { full_s: number; delta_s: number; kbps: number; [k: string]: number };
  rescan_rule_ids: string[];
}

export interface BulletinResult { bulletin_id: string; hosts_affected: string[]; findings: FindingPlus[]; scan_id: string | null }

export interface IngestHistory { deltas: DeltaReport[]; bulletins: Record<string, unknown>[] }

export interface OutboxEntry { id?: string; name: string; kind: string; bytes: number; created_at?: string; synced_at?: string; seconds?: number }
export interface Outbox { connected: boolean; pending: OutboxEntry[]; synced: OutboxEntry[] }
export interface SyncResult { sent: number; bytes: number; seconds: number }

export interface ScoreItem { id: string; kind: string; what: string; found: boolean; finding_ids: string[] }
export interface Score { seeded: number; found: number; share: number; items: ScoreItem[] }

export interface DemoStatus { available: boolean; loaded: boolean; targets: string[]; simulate_verify_fail_next: boolean }

export interface ApiErrorBody { detail: string }

// -- discovery (/api/v1/discovery, docs/DISCOVERY.md) --------------------------------------------
export const DISCOVERY_MODES = ['quick', 'full', 'passive', 'simulated'] as const;
export type DiscoveryMode = (typeof DISCOVERY_MODES)[number];
export type DiscoveryStatus = 'new' | 'known' | 'ignored' | 'missing';

export interface DiscoveryScope {
  cidr: string;
  allow_public: boolean;
  added_by: string;
  added_at: string;
  reason: string;
  scanner_target: string | null;
}

export interface DiscoveryRun {
  id: string;
  mode: string;
  status: string;
  started_at: string;
  finished_at: string | null;
  scopes: string[];
  hosts_seen: number;
  new: number;
  known: number;
  changed: number;
  missing: number;
  errors: string[];
  requested_by: string;
  asset_ids: string[];
}

export interface DiscoveryOverview {
  scopes: DiscoveryScope[];
  last_run: DiscoveryRun | null;
  counts: Partial<Record<DiscoveryStatus, number>>;
}

export interface OpenPort { port: number; proto: string; service: string; product: string; version: string; banner: string }

export interface DiscoveryChange { kind: string; detail?: string; [k: string]: unknown }

export interface DiscoveredAsset {
  id: string;
  address: string | null;
  hostname: string | null;
  mac: string | null;
  vendor: string | null;
  open_ports: OpenPort[];
  os_guess: string | null;
  os_accuracy: number | null;
  asset_type_guess: string;
  confidence: number;
  evidence: string[];
  sources: string[];
  first_seen: string;
  last_seen: string;
  status: DiscoveryStatus;
  inventory_target_id: string | null;
  notes: string;
  facts: Record<string, unknown>;
  changes: DiscoveryChange[];
}

export interface DiscoveryAccept {
  name?: string;
  asset_type?: string;
  transport?: string;
  username?: string;
  credential_ref?: string;
  in_scope: boolean;
  reason: string;
}
