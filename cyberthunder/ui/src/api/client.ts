// Typed fetch wrapper for /api/v1. Every request carries X-Actor (the name typed in Settings).
// Errors come back as ApiError with the server's {detail} verbatim.
import type {
  AssetFacts, AuditPage, AuditRecord, AuditVerify, AutomationPolicy, BulkResult, BulletinResult, DeltaReport,
  DemoStatus, Explanation, FindingPlus, FindingsPage, IngestHistory, KillStatus, LinkState, Outbox,
  PolicyDecision, ProposalDiff, ProposalPlus, ScanRequest, ScanRun, Score, Status, SyncResult, Target,
} from './types';

export const API_BASE = '/api/v1';
const ACTOR_KEY = 'ct.actor';

export function getActor(): string {
  try {
    return localStorage.getItem(ACTOR_KEY) ?? '';
  } catch {
    return '';
  }
}

export function setActor(name: string): void {
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
  constructor(status: number, detail: string) {
    super(detail);
    this.status = status;
    this.detail = detail;
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

async function parseError(res: Response): Promise<ApiError> {
  let detail = `${res.status} ${res.statusText}`;
  try {
    const text = await res.text();
    try {
      const body = JSON.parse(text) as { detail?: unknown };
      if (typeof body.detail === 'string') detail = body.detail;
      else if (body.detail !== undefined) detail = JSON.stringify(body.detail);
      else if (text) detail = text;
    } catch {
      if (text) detail = text;
    }
  } catch {
    /* keep status text */
  }
  return new ApiError(res.status, detail);
}

export async function request<T>(method: string, path: string, opts: { query?: Query; body?: unknown; form?: FormData } = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' };
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
  if (!res.ok) throw await parseError(res);
  const ct = res.headers.get('content-type') ?? '';
  if (ct.includes('application/json')) return (await res.json()) as T;
  return (await res.text()) as unknown as T;
}

const get = <T>(p: string, query?: Query) => request<T>('GET', p, { query });
const post = <T>(p: string, body?: unknown) => request<T>('POST', p, { body: body ?? {} });
const put = <T>(p: string, body?: unknown) => request<T>('PUT', p, { body: body ?? {} });
const del = <T>(p: string) => request<T>('DELETE', p);

const enc = encodeURIComponent;

export const api = {
  status: () => get<Status>('/status'),

  targets: () => get<{ targets: Target[] }>('/targets'),
  addTarget: (t: Partial<Target>) => post<Target>('/targets', t),
  updateTarget: (id: string, t: Partial<Target> & { reason?: string }) => put<Target>(`/targets/${enc(id)}`, t),
  removeTarget: (id: string) => del<{ ok: boolean }>(`/targets/${enc(id)}`),
  discover: (id: string) => post<AssetFacts>(`/targets/${enc(id)}/discover`),
  discovery: () => get<unknown>('/discovery'),

  startScan: (req: ScanRequest) => post<ScanRun>('/scans', req),
  scans: () => get<{ scans: ScanRun[] }>('/scans'),
  scan: (id: string) => get<ScanRun>(`/scans/${enc(id)}`),

  findings: (q: Query) => get<FindingsPage>('/findings', q),
  finding: (id: string) => get<FindingPlus>(`/findings/${enc(id)}`),
  propose: (id: string) => post<ProposalPlus>(`/findings/${enc(id)}/propose`),
  explain: (id: string, force = false) => post<Explanation>(`/findings/${enc(id)}/explain`, { force }),
  explainAll: (ids?: string[]) => post<{ queued: number }>('/findings/explain', ids ? { ids } : {}),

  proposals: (q?: Query) => get<{ proposals: ProposalPlus[] }>('/proposals', q),
  proposal: (id: string) => get<ProposalPlus>(`/proposals/${enc(id)}`),
  approve: (id: string, note?: string) => post<ProposalPlus>(`/proposals/${enc(id)}/approve`, { note }),
  deny: (id: string, note?: string) => post<ProposalPlus>(`/proposals/${enc(id)}/deny`, { note }),
  cancel: (id: string, note?: string) => post<ProposalPlus>(`/proposals/${enc(id)}/cancel`, { note }),
  apply: (id: string, simulate_verify_fail?: boolean) =>
    post<{ proposal_id: string; state: string }>(`/proposals/${enc(id)}/apply`, simulate_verify_fail ? { simulate_verify_fail } : {}),
  rollback: (id: string) => post<unknown>(`/proposals/${enc(id)}/rollback`),
  diff: (id: string) => get<ProposalDiff>(`/proposals/${enc(id)}/diff`),
  bulk: (action: 'approve' | 'deny', ids: string[], note?: string) => post<BulkResult>('/proposals/bulk', { action, ids, note }),

  audit: (q?: Query) => get<AuditPage>('/audit', q),
  auditVerify: () => get<AuditVerify>('/audit/verify'),

  kill: () => get<KillStatus>('/kill'),
  killEngage: (reason: string) => post<KillStatus>('/kill/engage', { reason }),
  killRelease: (reason: string) => post<KillStatus>('/kill/release', { reason }),

  policy: () => get<AutomationPolicy>('/policy'),
  putPolicy: (p: { enabled: boolean; reason?: string | null; rules: AutomationPolicy['rules'] }) => put<AutomationPolicy>('/policy', p),
  evaluatePolicy: (proposal_id: string) => post<PolicyDecision>('/policy/evaluate', { proposal_id }),

  link: () => get<LinkState>('/ingest/link'),
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
  outbox: () => get<Outbox>('/outbox'),
  sync: () => post<SyncResult>('/outbox/sync'),

  score: (scan_id?: string) => get<Score>('/reports/score', { scan_id }),
  queueReport: (kind: 'commander' | 'poam' | 'checklist', scan_id?: string, host?: string) =>
    post<unknown>('/reports/queue', { kind, scan_id, host }),
  reportText: (path: string, q?: Query) => get<string>(path, q),

  demo: () => get<DemoStatus>('/demo'),
  demoLoad: () => post<{ targets: Target[] }>('/demo/load'),
  demoReset: () => post<{ ok: boolean }>('/demo/reset'),
  demoToggle: (simulate_verify_fail_next: boolean) => put<DemoStatus>('/demo', { simulate_verify_fail_next }),
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
  let lastSeq = opts.afterSeq ?? 0;
  let es: EventSource | null = null;
  let stopped = false;
  let retry = 1000;
  let timer: number | undefined;

  const connect = () => {
    if (stopped) return;
    opts.onState?.('connecting');
    es = new EventSource(url('/audit/stream', { after_seq: lastSeq }));
    es.onopen = () => {
      retry = 1000;
      opts.onState?.('open');
    };
    es.addEventListener('audit', (ev) => {
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
