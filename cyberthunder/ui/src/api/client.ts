// Typed fetch wrapper for /api/v1. Verified sessions carry an opaque cookie and CSRF protection.
// Errors come back as ApiError with the server's {detail} verbatim.
import type {
  PublicationIntent, AssetFacts, AuditPage, AuditRecord, AuditVerify, AutomationPolicy, BulkResult, BulletinResult, ContentManifest, DeltaReport,
  DemoStatus, DiscoveredAsset, DiscoveredTarget, DiscoveryAccept, Finding, DiscoveryMode, DiscoveryOverview, DiscoveryRun, DiscoveryScope,
  DiscoveryStatus, Explanation, FindingPlus, FindingsPage, FindingsQuery, HeldContent, ImportDirResult, IngestHistory, KillStatus, LinkState,
  Outbox, PolicyDecision, ProposalDiff, ProposalPlan, ProposalPlus, PullJob, ReceivedCve, ReceivedStig, ScanRequest, ScanRun, Score, Status, SyncResult, Target,
  ReportHistory, SavedReportContent, TargetOutcome, TargetReport, UpdateCheck,
  ContentUploadResult, LibraryPreferences, LibraryPreferencesInput, StigLibrary, FindingReviewHistory, FindingReviewInput, ImpactReceipt,
  VulnerabilityJob, VulnerabilitySettings, VulnerabilitySettingsInput, VulnerabilityStatus,
  HostRegistration, RuntimeContext, TargetReadiness, ScopeRangeInput, ScopeRangePreview, SavedScopeRanges, VsphereRun, VsphereRunSummary,
} from './types';
import { sessionIdentity, sessionHeaders, sessionExpired, authorityRevision, parseStepUpChallenge, stepUpRequired, type StepUpChallenge } from './identity';

export const API_BASE = '/api/v1';
const ACTOR_KEY = 'ct.actor';

export function getActor(): string {
  const session = sessionIdentity();
  if (session && session.mode !== 'dev') return session.principal?.actor ?? '';
  try {
    return localStorage.getItem(ACTOR_KEY) ?? '';
  } catch {
    return '';
  }
}

export function setActor(name: string): void {
  if (sessionIdentity()?.mode !== 'dev' && sessionIdentity() !== null) return;
  try {
    localStorage.setItem(ACTOR_KEY, name.trim());
  } catch {
    /* storage unavailable: the name lives for this page only */
  }
  window.dispatchEvent(new CustomEvent('ct:actor', { detail: name.trim() }));
}

export class ApiError extends Error {
  status: number;
  detail: string;
  stepUp?: StepUpChallenge;
  constructor(status: number, detail: string, stepUp?: StepUpChallenge) {
    super(detail);
    this.status = status;
    this.detail = detail;
    this.stepUp = stepUp;
  }
}

type Query = Record<string, string | number | boolean | null | undefined>;

export function qs(q?: Query): string {
  if (!q) return '';
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) {
    if (v === undefined || v === null || v === '') continue;
    p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : '';
}

export function url(path: string, q?: Query): string {
  return `${API_BASE}${path}${qs(q)}`;
}

function requireAuthority(revision: number): void {
  if (revision !== authorityRevision()) throw new ApiError(0, 'Account permissions changed while the request was pending. Review and submit again.');
}

async function parseError(res: Response, revision: number): Promise<ApiError> {
  let detail = `${res.status} ${res.statusText}`;
  let challenge: StepUpChallenge | undefined;
  try {
    const text = await res.text();
    try {
      const body = JSON.parse(text) as { detail?: unknown };
      if (res.status === 401) challenge = parseStepUpChallenge(body);
      if (typeof body.detail === 'string') detail = body.detail;
      else if (body.detail !== undefined) detail = JSON.stringify(body.detail);
      else if (text) detail = text;
    } catch {
      if (text) detail = text;
    }
  } catch {
    /* keep status text */
  }
  requireAuthority(revision);
  if (res.status === 401) {
    if (challenge) stepUpRequired(challenge);
    else sessionExpired();
  }
  return new ApiError(res.status, detail, challenge);
}

export async function request<T>(method: string, path: string, opts: { query?: Query; body?: unknown; form?: FormData } = {}): Promise<T> {
  const revision = authorityRevision();
  const headers: Record<string, string> = { Accept: 'application/json', ...sessionHeaders(method) };
  const actor = getActor();
  if (actor) headers['X-Actor'] = actor;
  let body: BodyInit | undefined;
  if (opts.form) body = opts.form;
  else if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(opts.body);
  }
  let res: Response;
  try {
    res = await fetch(url(path, opts.query), { method, headers, body });
  } catch (e) {
    throw new ApiError(0, `API unreachable: ${(e as Error).message}`);
  }
  requireAuthority(revision);
  if (!res.ok) throw await parseError(res, revision);
  const ct = res.headers.get('content-type') ?? '';
  try {
    return (ct.includes('application/json') ? await res.json() : await res.text()) as T;
  } finally {
    // A malformed old response must not publish its parser error to a new account.
    requireAuthority(revision);
  }
}

const get = <T>(p: string, query?: Query) => request<T>('GET', p, { query });
const post = <T>(p: string, body?: unknown) => request<T>('POST', p, { body: body ?? {} });
const put = <T>(p: string, body?: unknown) => request<T>('PUT', p, { body: body ?? {} });
const del = <T>(p: string) => request<T>('DELETE', p);

const enc = encodeURIComponent;

async function vulnerabilityZip(path: 'import', file: File): Promise<VulnerabilityStatus>;
async function vulnerabilityZip(path: 'export'): Promise<Blob>;
async function vulnerabilityZip(path: 'import' | 'export', file?: File): Promise<VulnerabilityStatus | Blob> {
  const revision = authorityRevision();
  const headers: Record<string, string> = { Accept: path === 'export' ? 'application/zip' : 'application/json', ...sessionHeaders('POST') };
  const actor = getActor();
  if (actor) headers['X-Actor'] = actor;
  if (file) headers['Content-Type'] = 'application/zip';
  let res: Response;
  try {
    res = await fetch(url(`/vulnerabilities/${path}`), { method: 'POST', headers, body: file });
  } catch (e) {
    throw new ApiError(0, `API unreachable: ${(e as Error).message}`);
  }
  requireAuthority(revision);
  if (!res.ok) throw await parseError(res, revision);
  // Consume the body before returning so a late export cannot cross accounts.
  try {
    return path === 'export' ? await res.blob() : await res.json() as VulnerabilityStatus;
  } finally {
    requireAuthority(revision);
  }
}

export const api = {
  status: () => get<Status>('/status'),

  vulnerabilities: () => get<VulnerabilityStatus>('/vulnerabilities'),
  saveVulnerabilitySettings: (body: VulnerabilitySettingsInput) => put<VulnerabilitySettings>('/vulnerabilities/settings', body),
  updateVulnerabilityDatabases: (include_java: boolean) => post<VulnerabilityJob>('/vulnerabilities/update', { include_java }),
  vulnerabilityJobs: () => get<{ jobs: VulnerabilityJob[] }>('/vulnerabilities/jobs'),
  vulnerabilityJob: (id: string) => get<VulnerabilityJob>(`/vulnerabilities/jobs/${enc(id)}`),
  importVulnerabilityBundle: (file: File): Promise<VulnerabilityStatus> => vulnerabilityZip('import', file),
  exportVulnerabilityBundle: (): Promise<Blob> => vulnerabilityZip('export'),

  targets: () => get<{ targets: Target[] }>('/targets'),
  runtimeContext: () => get<RuntimeContext>('/runtime/context'),
  registerHost: (body: HostRegistration) => post<Target>('/targets/register-host', body),
  targetReadiness: (id: string) => get<TargetReadiness>(`/targets/${enc(id)}/readiness`),
  addTarget: (t: Partial<Target>) => post<Target>('/targets', t),
  updateTarget: (id: string, t: Partial<Target> & { reason?: string }) => put<Target>(`/targets/${enc(id)}`, t),
  removeTarget: (id: string) => del<{ ok: boolean }>(`/targets/${enc(id)}`),
  discover: (id: string) => post<AssetFacts>(`/targets/${enc(id)}/discover`),

  discovery: () => get<DiscoveryOverview>('/discovery'),
  previewScopeRanges: (body: ScopeRangeInput) => post<ScopeRangePreview>('/discovery/scopes/preview', body),
  saveScopeRanges: (body: ScopeRangeInput & { reason: string }) => put<SavedScopeRanges>('/discovery/scopes/ranges', body),
  putDiscoveryScopes: (scopes: { cidr: string; allow_public?: boolean; scanner_target?: string | null }[], reason: string) =>
    put<{ scopes: DiscoveryScope[] }>('/discovery/scopes', { scopes, reason }),
  sweep: (mode: DiscoveryMode, scopes?: string[]) =>
    post<DiscoveryRun>('/discovery/sweep', scopes && scopes.length ? { mode, scopes } : { mode }),
  discoveryRuns: () => get<DiscoveryRun[]>('/discovery/runs'),
  discoveryRun: (id: string) => get<DiscoveryRun & { assets: DiscoveredAsset[] }>(`/discovery/runs/${enc(id)}`),
  vsphereCollect: (id: string) => post<VsphereRun>(`/discovery/vsphere/${enc(id)}/collect`),
  vsphereRuns: (id: string) => get<VsphereRunSummary[]>(`/discovery/vsphere/${enc(id)}/runs`, { limit: 20 }),
  vsphereRun: (id: string, run: string) => get<VsphereRun>(`/discovery/vsphere/${enc(id)}/runs/${enc(run)}`),
  discoveredAssets: (status?: DiscoveryStatus) => get<DiscoveredAsset[]>('/discovery/assets', { status }),
  discoveredAsset: (id: string) => get<DiscoveredAsset>(`/discovery/assets/${enc(id)}`),
  acceptAsset: (id: string, body: DiscoveryAccept) => post<Target>(`/discovery/assets/${enc(id)}/accept`, body),
  ignoreAsset: (id: string, reason: string) => post<DiscoveredAsset>(`/discovery/assets/${enc(id)}/ignore`, { reason }),
  discoveryFindings: (run_id?: string) => get<Finding[]>('/discovery/findings', { run_id }),

  startScan: (req: ScanRequest) => post<ScanRun>('/scans', req),
  scans: () => get<{ scans: ScanRun[] }>('/scans'),
  scan: (id: string) => get<ScanRun>(`/scans/${enc(id)}`),

  findings: (q: FindingsQuery) => get<FindingsPage>('/findings', q),
  finding: (id: string) => get<FindingPlus>(`/findings/${enc(id)}`),
  findingReview: (id: string, scan_id?: string) => get<FindingReviewHistory>(`/findings/${enc(id)}/review`, { scan_id }),
  saveFindingReview: (id: string, body: FindingReviewInput) => put<FindingReviewHistory>(`/findings/${enc(id)}/review`, body),
  acceptFindingRisk: (id: string, body: import('./types').RiskAcceptanceInput) => put<FindingReviewHistory>(`/findings/${enc(id)}/risk-acceptance`, body),
  revokeFindingRisk: (id: string, body: import('./types').RiskRevocationInput) => post<FindingReviewHistory>(`/findings/${enc(id)}/risk-acceptance/revoke`, body),
  propose: (id: string) => post<ProposalPlus>(`/findings/${enc(id)}/propose`),
  explain: (id: string, force = false) => post<Explanation>(`/findings/${enc(id)}/explain`, { force }),
  explainAll: (ids?: string[]) => post<{ queued: number }>('/findings/explain', ids ? { ids } : {}),

  proposals: (q?: Query) => get<{ proposals: ProposalPlus[] }>('/proposals', q),
  proposal: (id: string) => get<ProposalPlus>(`/proposals/${enc(id)}`),
  plan: (id: string) => post<ProposalPlan>(`/proposals/${enc(id)}/plan`),
  approve: (id: string, note?: string, assessmentId?: string, assessmentNote?: string) =>
    post<ProposalPlus>(`/proposals/${enc(id)}/approve`, { note, assessment_id: assessmentId, assessment_note: assessmentNote }),
  assessImpact: (id: string, live = true) => post<ImpactReceipt>(`/proposals/${enc(id)}/impact`, { live }),
  latestImpact: (id: string) => get<{ assessment: ImpactReceipt | null }>(`/proposals/${enc(id)}/impact`),
  impactReceipt: (id: string) => get<ImpactReceipt>(`/change-assessments/${enc(id)}`),
  reviewImpact: (id: string, assessmentId: string, note?: string) =>
    post<ProposalPlus>(`/proposals/${enc(id)}/review-impact`, { assessment_id: assessmentId, note }),
  deny: (id: string, note?: string) => post<ProposalPlus>(`/proposals/${enc(id)}/deny`, { note }),
  cancel: (id: string, note?: string) => post<ProposalPlus>(`/proposals/${enc(id)}/cancel`, { note }),
  apply: (id: string, simulate_verify_fail?: boolean) =>
    post<{ proposal_id: string; state: string }>(`/proposals/${enc(id)}/apply`, simulate_verify_fail ? { simulate_verify_fail } : {}),
  rollback: (id: string) => post<unknown>(`/proposals/${enc(id)}/rollback`),
  diff: (id: string) => get<ProposalDiff>(`/proposals/${enc(id)}/diff`),
  verify: (id: string) => post<ProposalPlus>(`/proposals/${enc(id)}/verify`),
  bulk: async (action: 'approve' | 'deny', ids: string[], note?: string) => {
    const result = await post<BulkResult>('/proposals/bulk', { action, ids, note });
    for (const item of result.results) {
      if (!('error' in item) || item.status !== 401) continue;
      const challenge = parseStepUpChallenge({ error: item.code, step_up: item.step_up });
      if (challenge) { stepUpRequired(challenge); break; }
    }
    return result; // Earlier decisions remain visible; the caller must never replay the batch.
  },

  audit: (q?: Query) => get<AuditPage>('/audit', q),
  auditVerify: () => get<AuditVerify>('/audit/verify'),

  kill: () => get<KillStatus>('/kill'),
  killEngage: (reason: string) => post<KillStatus>('/kill/engage', { reason }),
  killRelease: (reason: string) => post<KillStatus>('/kill/release', { reason }),

  policy: () => get<AutomationPolicy>('/policy'),
  putPolicy: (p: { enabled: boolean; reason?: string | null; rules: AutomationPolicy['rules'] }) => put<AutomationPolicy>('/policy', p),
  evaluatePolicy: (proposal_id: string) => post<PolicyDecision>('/policy/evaluate', { proposal_id }),

  link: () => get<LinkState>('/ingest/link'),
  probeLink: () => post<unknown>('/ingest/link/probe'),
  putLink: (l: Partial<LinkState>) => put<LinkState>('/ingest/link', l),
  ingestStig: (file: File) => {
    const form = new FormData();
    form.append('file', file);
    return request<DeltaReport>('POST', '/ingest/stig', { form });
  },
  rescanDelta: (id: string) => post<ScanRun>(`/ingest/stig/${enc(id)}/rescan`),
  ingestBulletin: (file: File) => {
    const form = new FormData();
    form.append('file', file);
    return request<BulletinResult>('POST', '/ingest/bulletin', { form });
  },
  ingestHistory: () => get<IngestHistory>('/ingest/history'),
  updates: () => get<UpdateCheck>('/ingest/updates'),
  checkUpdates: (source: 'live' | 'snapshot' = 'live') => post<UpdateCheck>('/ingest/updates/check', { source }),
  pullUpdates: (body: { filenames?: string[]; all_matching?: boolean; pace?: boolean }) => post<PullJob>('/ingest/updates/pull', body),
  pullJob: (id: string) => get<PullJob>(`/ingest/updates/jobs/${enc(id)}`),
  content: () => get<HeldContent>('/ingest/content'),
  stigLibrary: () => get<StigLibrary>('/ingest/library'),
  saveLibraryPreferences: (body: LibraryPreferencesInput) => put<LibraryPreferences>('/ingest/library/preferences', body),
  uploadContent: (file: File, overrideReason?: string, publicationIntent?: PublicationIntent) => {
    const form = new FormData();
    form.append('file', file);
    if (overrideReason !== undefined) form.append('override_reason', overrideReason);
    if (publicationIntent !== undefined) form.append('publication_intent', JSON.stringify(publicationIntent));
    return request<ContentUploadResult>('POST', '/ingest/content/upload', { form });
  },
  writeManifest: () => post<ContentManifest>('/ingest/manifest'),
  importDir: (path: string, overrideReason?: string, publicationIntent?: PublicationIntent) => post<ImportDirResult>('/ingest/import-dir', { path, override_reason: overrideReason, publication_intent: publicationIntent }),
  outbox: () => get<Outbox>('/outbox'),
  sync: () => post<SyncResult>('/outbox/sync'),

  score: (scan_id?: string) => get<Score>('/reports/score', { scan_id }),
  reportHistory: (q?: Query) => get<ReportHistory>('/reports/history', q),
  savedReport: (id: string) => get<SavedReportContent>(`/reports/history/${enc(id)}`),
  queueReport: (kind: 'commander' | 'poam' | 'checklist', scan_id?: string, host?: string) =>
    post<unknown>('/reports/queue', { kind, scan_id, host }),
  reportText: (path: string, q?: Query) => get<string>(path, q),

  demo: () => get<DemoStatus>('/demo'),
  demoLoad: () => post<{ targets: Target[] }>('/demo/load'),
  demoReset: () => post<{ ok: boolean }>('/demo/reset'),
  demoToggle: (simulate_verify_fail_next: boolean) => put<DemoStatus>('/demo', { simulate_verify_fail_next }),

  receiveCves: () => get<{ cves: ReceivedCve[] }>('/receive/cve'),
  receiveStigs: () => get<{ stigs: ReceivedStig[] }>('/receive/stig'),
  discoverSystem: (system: string) => post<{ targets: DiscoveredTarget[] }>('/discover', { system }),
  scanTarget: (target: string, modules?: string[]) =>
    post<{ target: string; results: Record<string, TargetOutcome> }>('/scan', modules ? { target, modules } : { target }),
  explainResults: (results: unknown) => post<{ explanations: Explanation[]; truncated: number }>('/generate/explain', { results }),
  proposeResults: (results: unknown) => post<{ proposals: ProposalPlus[]; skipped: { id: string; reason: string }[] }>('/generate/propose', { results }),
  applyChecklists: (targets: string[], checklists: string[]) =>
    post<{ results: Record<string, TargetOutcome> }>('/apply', { targets, checklists }),
  rollbackVersions: (targets: string[], versions: string[]) =>
    post<{ results: Record<string, TargetOutcome> }>('/rollback', { targets, versions }),
  targetReport: (target: string) => get<TargetReport>(`/reports/${enc(target)}`),
  generateTargetReport: (target: string) => post<TargetReport>('/reports', { target }),
};

/** Error text for display: the API detail verbatim when we have one. */
export function errorText(e: unknown): string {
  if (e instanceof ApiError) return e.detail;
  if (e instanceof Error) return e.message;
  return String(e);
}

// -- SSE: /audit/stream with reconnect from the last seen seq ------------------------------------
export type AuditStreamState = 'connecting' | 'open' | 'closed';

export function subscribeAudit(
  onRecord: (r: AuditRecord) => void,
  opts: { afterSeq?: number; onState?: (s: AuditStreamState) => void } = {},
): () => void {
  const revision = authorityRevision();
  let lastSeq = opts.afterSeq ?? 0;
  let es: EventSource | null = null;
  let stopped = false;
  let retry = 1000;
  let timer: number | undefined;

  const connect = () => {
    if (stopped || revision !== authorityRevision()) return;
    opts.onState?.('connecting');
    es = new EventSource(url('/audit/stream', { after_seq: lastSeq }));
    es.onopen = () => {
      retry = 1000;
      opts.onState?.('open');
    };
    es.addEventListener('audit', (ev) => {
      if (revision !== authorityRevision()) return;
      try {
        const rec = JSON.parse((ev as MessageEvent<string>).data) as AuditRecord;
        if (rec.seq > lastSeq) {
          lastSeq = rec.seq;
          onRecord(rec);
        }
      } catch {
        /* ignore malformed event */
      }
    });
    es.addEventListener('session-expired', () => {
      stopped = true;
      es?.close();
      if (revision === authorityRevision()) sessionExpired();
    });
    es.onerror = () => {
      es?.close();
      es = null;
      opts.onState?.('closed');
      if (stopped) return;
      timer = window.setTimeout(connect, retry);
      retry = Math.min(retry * 2, 15000);
    };
  };
  connect();
  return () => {
    stopped = true;
    if (timer) window.clearTimeout(timer);
    es?.close();
  };
}
