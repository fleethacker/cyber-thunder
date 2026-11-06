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

export type ConfidenceGrade = 'high' | 'medium' | 'low' | 'unknown';
export interface FindingConfidence {
  grade: ConfidenceGrade;
  reason: string;
  reasons: string[];
  version: string;
  assessed_at: string;
  observed_at: string | null;
  evidence: Record<string, unknown>;
}
export type ReviewDisposition = 'unreviewed' | 'confirmed' | 'false_positive' | 'not_applicable' | 'needs_investigation';
export interface FindingReviewEvent {
  id: string;
  disposition: ReviewDisposition;
  reason: string;
  supporting_evidence: string;
  expires_at: string | null;
  reviewed_at: string;
  reviewed_by: string;
  identity_verified: false;
  scope: Record<string, unknown>;
  evidence_fingerprint: string;
}
export interface FindingReview {
  disposition: ReviewDisposition;
  active: boolean;
  suppressed: boolean;
  revision: number;
  evidence_fingerprint: string;
  current: FindingReviewEvent | null;
  history_count: number;
  reopened_reason: string | null;
  identity_verified: false;
}
export interface FindingReviewHistory extends FindingReview { history: FindingReviewEvent[] }
export interface FindingReviewInput {
  disposition: ReviewDisposition;
  reason: string;
  supporting_evidence: string;
  expires_at: string | null;
  expected_revision: number;
  evidence_fingerprint: string;
}

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

/** POST /proposals/{id}/plan: library metadata only; no target connection or execution. */
export interface ProposalPlan {
  version: 1;
  mode: 'static';
  generated_at: string;
  proposal_id: string;
  proposal_state: ProposalState;
  target: { id: string; name: string | null; asset_type: string | null; simulated: boolean | null; in_scope: boolean | null };
  fix: FixEntry;
  fix_sha256: string;
  approved_fix_sha256: string | null;
  checks: { code: string; status: 'pass' | 'blocked' | 'unknown'; detail: string }[];
  limitations: string[];
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
  scanner_status?: FindingStatus;
  confidence?: FindingConfidence | null;
  review?: FindingReview | null;
  remediated?: { proposal_id: string; verified_at: string; scan_status: FindingStatus } | null;
  needs_rescan?: boolean;
  rollback?: { proposal_id: string; finished_at: string | null; ok: boolean } | null;
  categories: FindingCategory[];
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
  view: 'current' | 'scan';
  unfiltered_total: number;
  facets: Partial<Record<FindingFacet, FindingFacetOption[]>>;
  limit: number;
  offset: number;
  sort_by: FindingSort;
  sort_dir: SortDirection;
}

export type FindingCategory = 'stig' | 'cve' | 'hunt' | 'other';
export type FindingFacet = 'host' | 'asset_type' | 'source' | 'status' | 'severity' | 'category' | 'benchmark' | 'benchmark_release' | 'confidence' | 'review';
export interface FindingFacetOption { value: string; label: string; count: number }
export type FindingSort = 'default' | 'severity' | 'host' | 'asset_type' | 'category' | 'title' | 'rule_id' | 'rule_version' | 'source' | 'collected_at' | 'benchmark' | 'benchmark_release' | 'confidence' | 'review';
export type SortDirection = 'asc' | 'desc';
export type FindingsQuery = Partial<Record<FindingFacet | 'scan_id' | 'q', string>> & {
  sort_by?: FindingSort; sort_dir?: SortDirection; limit?: number; offset?: number;
};

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
  decided_principal?: { iss: string; sub: string; name: string; verified: boolean; roles: string[] } | null;
  decided_at: string | null;
  decision_note: string | null;
  before_state_ref: string | null;
  history: HistoryEntry[];
  assessment?: { status: 'reviewed' | 'not_assessed'; id: string | null; note: string;
    risk_level?: string; has_unknowns?: boolean; model_used?: boolean; valid_until?: string } | null;
}

export interface ImpactEvidence {
  id: string; kind: string; source: string; observed_at: string; subject: string;
  facts: Record<string, unknown>;
}
export interface ImpactDependency {
  id: string; from: string; to: string; relation: string; evidence_ids: string[];
}
export interface ImpactReceipt {
  version: number; id: string; proposal_id: string; target_id: string;
  generated_at: string; valid_until: string; evidence_sha256: string; fix_sha256: string;
  evidence_packet: { mode: 'live' | 'stored'; complete: boolean; generated_at?: string; evidence: ImpactEvidence[] };
  assessment: { advisory_only: boolean; approval_authority: boolean;
    source: 'model_advisory' | 'deterministic_fallback'; risk_level: 'unknown' | 'low' | 'medium' | 'high' | 'critical';
    summary: string; evidence_ids: string[]; complete: boolean;
    risks: { id: string; severity: string; summary: string; deterministic: boolean; evidence_ids: string[] }[];
    dependencies: ImpactDependency[]; unknowns: string[]; required_checks: string[]; rollback_limits: string[] };
  model: { backend: string | null; name: string | null; used: boolean; validated: boolean;
    fallback_reason: string | null; attempts: number; input_coverage?: { limited: boolean } };
  freshness: { ready: boolean; status: string; stale: boolean; reasons: string[]; unknowns: string[];
    age_seconds: number | null; approval_authority: false };
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

/** Static restore checks; missing fields on a failed lookup are unknown, never permission. */
export interface RollbackGuard {
  status: 'not_checked' | 'blocked' | 'checked_files' | 'limited';
  coverage: 'files' | 'partial' | 'unsupported' | 'unavailable' | 'unknown';
  live_checked: boolean;
  identity_bound?: boolean;
  transition_allowed?: boolean;
  conflicting_proposals?: string[];
  reasons: string[];
  limitations?: string[];
  /** An earlier attempt, not current authorization or a fresh live check. */
  last_preflight?: Omit<RollbackGuard, 'last_preflight'> & { checked_at?: string } | null;
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
  rollback_guard?: RollbackGuard | null;
  files: DiffFile[];
}

export type BulkItem = { id: string; state: ProposalState } | { id: string; error: string };
export interface BulkResult { results: BulkItem[] }

export interface Target {
  id: string;
  name: string;
  environment?: string;
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

/** Local runtime markers only; neither the physical deployment host nor connectivity is inferred. */
export interface RuntimeContext {
  kind: 'native' | 'container' | 'kubernetes' | 'unknown';
  detection: 'local_markers' | 'no_container_markers' | 'unknown';
  runtime_os: 'linux' | 'windows' | 'darwin' | 'unknown';
  physical_host_os: 'unknown';
  host_address: null;
  host_address_required: true;
  local_transport: { boundary: 'container' | 'runtime' | 'unknown'; description: string };
  supported_host_transports: ('ssh' | 'winrm')[];
  hints: { code: string; message: string }[];
}

export interface HostRegistration {
  id: string;
  name: string;
  asset_type: 'linux' | 'windows';
  transport: 'ssh' | 'winrm';
  address: string;
  port?: number | null;
  username: string;
  credential_ref: string;
  sudo?: boolean;
  in_scope: boolean;
  reason: string;
}

export interface TargetReadiness {
  target_id: string;
  ready_for_connection_test: boolean;
  checked: 'declarations_only';
  connection_test_route: string;
  checks: { code: string; status: 'ok' | 'blocked' | 'unknown'; message: string }[];
  warnings: string[];
  runtime: RuntimeContext;
}

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

export interface LinkObservation { at: string; endpoint: string; method: string; application_bytes: number; elapsed_seconds: number; success: boolean; status: number | null; observed_kbps: number | null; test_mode: boolean; error?: string | null }
export interface LinkState {
  kbps: number | null; latency_ms: number | null; connected: boolean;
  mode: "production" | "test"; offline_override: boolean; test_connected: boolean;
  reachability: string; observed_kbps: number | null; last_observation: LinkObservation | null;
  rate_observation?: LinkObservation | null;
  observations: LinkObservation[]; probe_enabled: boolean; probe_until: number | null; probe_endpoint: string;
}

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

export interface OutboxEntry { id?: string; name: string; kind: string; bytes: number; created_at?: string; synced_at?: string; seconds?: number | null; transfer_kind?: string; test_estimate_seconds?: number | null }
export interface Outbox { link?: LinkState; connected: boolean; pending: OutboxEntry[]; synced: OutboxEntry[] }
export interface SyncResult { sent: number; bytes: number; seconds: number }

export interface ScoreItem { id: string; kind: string; what: string; found: boolean; finding_ids: string[] }
export interface Score { seeded: number; found: number; share: number; items: ScoreItem[] }

export type ReportKind = 'commander' | 'poam' | 'checklist' | 'target';
export interface SavedReport {
  id: string;
  kind: ReportKind;
  title: string;
  format: string;
  generated_at: string;
  generated_by: string;
  scan_id: string | null;
  targets: string[];
  target_names: string[];
  filename: string;
  media_type: string;
  bytes: number;
}
export interface ReportHistory { reports: SavedReport[]; total: number; offset: number; limit: number }
export interface SavedReportContent extends SavedReport { content: string }

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
  grant_id?: string;
}

export interface ScopeRangeInput {
  include: string[];
  exclude?: string[];
  allow_public?: boolean;
  scanner_target?: string | null;
  acknowledge_normalization?: boolean;
}

export interface ScopeRangePreview {
  networks: string[];
  network_count: number;
  input_address_count: string;
  excluded_address_count: string;
  address_count: string;
  truncated: boolean;
  can_save: boolean;
  blocking_reasons: string[];
  warnings: string[];
  normalizations: { field: 'include' | 'exclude'; input: string; normalized: string; recipe_id?: string; recipe_name?: string }[];
  requires_normalization_acknowledgment: boolean;
  limits: { max_entries: number; max_networks: number; max_addresses: number };
}

export interface SavedScopeRanges {
  scopes: DiscoveryScope[];
  preview: ScopeRangePreview;
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

// -- DISA content updates (docs/CONTENT.md) ------------------------------------------------------
export type ContentKind = 'manual_stig' | 'scap_benchmark' | 'srg' | 'automation' | 'compilation' | 'document' | 'tool' | 'other';

export interface ContentRow {
  filename: string;
  url: string;
  product_key: string | null;
  kind: ContentKind;
  version: number[] | null;
  version_label: string | null;
  upload_date: string | null;
  title?: string;
  sunset?: boolean;
  allowed?: boolean;
  targets?: string[];
  held_version?: number[] | null;
  expected_bytes?: number | null;
  expected_etag?: string | null;
}

export interface ContentSkip { target_id?: string; filename?: string; product_key?: string; kind?: string; reason: string }

export interface UpdateCheck {
  checked_at: string | null;
  checked_by?: string;
  source?: 'live' | 'snapshot';
  index_entries?: number;
  index_bytes?: number;
  index_wire_bytes?: number;
  gzip?: boolean;
  estimate_seconds_at_link?: number | null;
  index_estimate_seconds?: number | null;
  wanted: ContentRow[];
  updates: ContentRow[];
  current: ContentRow[];
  skipped: ContentSkip[];
  wanted_count?: number;
  new_count?: number;
  index_estimate?: { bytes: number; seconds: number; link: LinkState };
  connected?: boolean;
}

export interface PullDelta {
  id: string;
  benchmark_id: string;
  old_release: string | null;
  new_release: string | null;
  counts: Record<string, number>;
  rescan_rules: number;
  full_import: boolean;
  filename: string;
}

export interface PullFile {
  filename: string;
  url: string;
  kind: ContentKind | null;
  product_key: string | null;
  version_label: string | null;
  bytes: number;
  total: number | null;
  state: 'pending' | 'downloading' | 'verifying' | 'retrying' | 'done' | 'failed' | 'quarantined' | 'stopped';
  error: string | null;
  estimate_seconds: number | null;
  sha256: string | null;
  delta: PullDelta | null;
  datastream_path: string | null;
}

export interface PullJob {
  id: string;
  created_at: string;
  created_by: string;
  state: 'queued' | 'running' | 'done' | 'partial' | 'failed' | 'stopped';
  pace: boolean;
  files: PullFile[];
  deltas: PullDelta[];
  error: string | null;
  finished_at: string | null;
}

export interface HeldFile {
  filename: string;
  product_key: string | null;
  kind: ContentKind;
  version: number[] | null;
  version_label: string | null;
  upload_date: string | null;
  sha256: string;
  bytes: number;
  fetched_at: string | null;
  fetched_by: string | null;
  source: 'pulled' | 'imported' | 'uploaded' | 'bundled';
  benchmark_id?: string | null;
  benchmark_release?: string | null;
  ingest: {
    delta_id?: string;
    catalog_path?: string;
    datastream_path?: string;
    upload?: { filename: string; imported_at: string; imported_by: string; authenticity_verified: boolean };
  };
}

export interface HeldContent {
  files: HeldFile[];
  products: { product_key: string; files: HeldFile[] }[];
  scap: { product_key: string | null; filename: string; datastream_path: string }[];
  quarantine: { filename: string; reason: string; quarantined_at: string }[];
  dir: string;
}

export interface ContentManifest {
  generated_at: string;
  node: string | null;
  items: { filename: string; url: string; product_key: string | null; kind: string; version: number[] | null; expected_bytes?: number; expected_etag?: string }[];
  path: string;
  sha256: string;
}

export interface ImportDirResult {
  imported: HeldFile[];
  refused: { filename: string; reason: string }[];
  skipped: { filename: string; reason: string }[];
  missing: string[];
  verified_by: string;
  deltas: PullDelta[];
}

export type LibraryKind = 'manual_stig' | 'srg' | 'scap_benchmark';

export interface LibraryPreferences {
  mode: 'inventory' | 'selected';
  products: string[];
  kinds: LibraryKind[];
  check_on_reconnect: boolean;
  auto_pull: boolean;
  revision: number;
  updated_at: string | null;
  updated_by: string | null;
}

export type LibraryPreferencesInput = Omit<LibraryPreferences, 'updated_at' | 'updated_by'>;

export interface LibraryProduct {
  product_key: string;
  title: string;
  kinds: string[];
  recommended: boolean;
  selected: boolean;
  targets: string[];
  available: ContentRow[];
  held: HeldFile[];
  status: 'update_available' | 'current' | 'not_downloaded' | 'unavailable';
}

export interface LibraryCatalog {
  benchmark_id: string;
  title: string;
  release: string;
  rules: number;
  imported_at: string | null;
  filename: string;
  origin: 'imported_catalog' | 'bundled_reference';
  path: string;
}

export interface StigLibrary {
  catalog: { source: 'live' | 'snapshot'; saved_at: string | null; total_entries: number };
  sync: {
    last_attempt_at: string | null;
    last_attempt_status: string | null;
    last_error: string | null;
    last_successful_check_at: string | null;
    last_download_at: string | null;
    last_import_at: string | null;
  };
  preferences: LibraryPreferences;
  products: LibraryProduct[];
  selection: { wanted: ContentRow[]; updates: ContentRow[]; current: ContentRow[]; skipped: ContentSkip[] };
  held: HeldContent;
  catalogs: LibraryCatalog[];
  catalog_errors?: { filename: string; reason: string }[];
  jobs: PullJob[];
  connected: boolean;
  check_interval_s: number;
}

export interface ContentUploadResult { record: HeldFile; delta: PullDelta | null }

// -- Managed vulnerability databases -----------------------------------------------------------
export interface VulnerabilitySettings {
  revision: number;
  auto_update: boolean;
  interval_hours: number;
  include_java: boolean;
}

export type VulnerabilitySettingsInput = Omit<VulnerabilitySettings, 'revision'> & { expected_revision: number };

export interface VulnerabilityDatabase {
  kind: 'main' | 'java';
  present: boolean;
  schema: number | null;
  updated_at: string | null;
  next_update: string | null;
  downloaded_at: string | null;
  stale: boolean;
  sha256: string | null;
  bytes: number | null;
}

export interface VulnerabilityJob {
  id: string;
  kind: 'update';
  state: 'pending' | 'running' | 'completed' | 'failed' | 'stopped';
  started_at: string | null;
  finished_at: string | null;
  actor: string;
  error: string | null;
  generation: string | null;
}

export interface VulnerabilityStatus {
  version: 1;
  engine: { available: boolean; version: string | null; supported: boolean; error: string | null };
  state: 'missing' | 'invalid' | 'ready' | 'stale' | 'unavailable';
  generation: string | null;
  updated_at: string | null;
  imported_at: string | null;
  last_attempt: string | null;
  last_success: string | null;
  last_error: string | null;
  source: string | null;
  provenance: 'official_download' | 'offline_import' | 'unknown';
  integrity_verified: boolean;
  databases: VulnerabilityDatabase[];
  settings: VulnerabilitySettings;
  active_job: VulnerabilityJob | null;
  warnings: string[];
}

/** A Target returned by POST /discover. `facts` is set on the system that was read. */
export interface DiscoveredTarget extends Target {
  facts?: AssetFacts | null;
}

export interface ReceivedCve {
  id?: string;
  title?: string;
  severity?: string;
  cves?: string[];
  published?: string;
  source?: string;
  ingested_at?: string;
  hosts_affected?: string[];
  findings?: number;
  scan_id?: string | null;
}

export interface ReceivedStig {
  id?: string;
  benchmark_id?: string;
  old_release?: string | null;
  new_release?: string | null;
  counts?: Record<string, number>;
  created_at?: string;
  filename?: string;
  sizes?: Record<string, number>;
  transfer?: Record<string, number>;
}

export interface WorkflowSkip { id: string; reason: string }

export interface WorkflowChange { proposal_id: string; state: string; version: string }

/** Per-target outcome from /scan, /apply, and /rollback. */
export interface TargetOutcome {
  target: string;
  ok: boolean;
  errors: string[];
  skipped: WorkflowSkip[];
  scan_id?: string;
  status?: string;
  findings?: number;
  open?: number;
  applied?: WorkflowChange[];
  rolled_back?: WorkflowChange[];
}

export interface TargetReport {
  target: Target;
  generated_at: string;
  generated_by: string;
  findings: number;
  open: number;
  summary: Partial<FindingsSummary>;
  checklist: Record<string, unknown> | null;
  checklist_error: string | null;
}
