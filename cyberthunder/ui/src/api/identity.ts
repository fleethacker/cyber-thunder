// Session metadata only. Authentication tokens and credentials stay on the server.
export interface SessionIdentity {
  mode: 'dev' | 'oidc' | 'mesh';
  authenticated: boolean;
  login_available: boolean;
  csrf_token?: string;
  principal?: { actor: string; name: string; roles: string[]; kind?: string; expires_at?: number;
    issuer?: string; subject?: string; source?: string; verified?: boolean } | null;
  permissions: string[];
}

let current: SessionIdentity | null = null;
let revision = 0;
let currentAuthority = 'signed-out';

/** Authority only: display names, expiry ticks and array order do not reset a view. */
export function authorityKey(identity: SessionIdentity | null): string {
  if (!identity) return 'signed-out';
  const p = identity.principal;
  return JSON.stringify([identity.mode, identity.authenticated, p?.issuer, p?.subject, p?.actor,
    p?.source, p?.verified, p?.kind, [...new Set(p?.roles ?? [])].sort(),
    [...new Set(identity.permissions)].sort(), identity.csrf_token]);
}

export function authorityRevision(): number { return revision; }

export interface StepUpChallenge { reason: string; max_age: number; acr_values: string[] }
const STEP_UP_REASONS = ['assurance_not_configured', 'human_authentication_required', 'invalid_authentication_time',
  'future_authentication_time', 'authentication_too_old', 'assurance_not_accepted'];

export function parseStepUpChallenge(value: unknown): StepUpChallenge | undefined {
  if (!value || typeof value !== 'object') return;
  const body = value as Record<string, unknown>;
  if (body.error !== 'insufficient_user_authentication' || !body.step_up || typeof body.step_up !== 'object') return;
  const c = body.step_up as Record<string, unknown>;
  if (typeof c.reason !== 'string' || !STEP_UP_REASONS.includes(c.reason)
      || typeof c.max_age !== 'number' || !Number.isInteger(c.max_age) || c.max_age < 1 || c.max_age > 3600
      || !Array.isArray(c.acr_values) || c.acr_values.length > 8
      || c.acr_values.some(v => typeof v !== 'string' || !/^[\x21\x23-\x5b\x5d-\x7e]{1,128}$/.test(v))
      || new Set(c.acr_values).size !== c.acr_values.length) return;
  return { reason: c.reason, max_age: c.max_age, acr_values: [...c.acr_values] as string[] };
}

export function stepUpRequired(challenge: StepUpChallenge): void {
  if (current?.mode === 'dev') return;
  window.dispatchEvent(new CustomEvent('ct:step-up', { detail: challenge }));
}

export function sessionIdentity(): SessionIdentity | null { return current; }

export function setSessionIdentity(identity: SessionIdentity | null): void {
  const next = authorityKey(identity);
  if (next !== currentAuthority) revision++;
  currentAuthority = next;
  current = identity;
}

export function sessionHeaders(method: string): Record<string, string> {
  if (current?.authenticated && current.csrf_token && !['GET', 'HEAD', 'OPTIONS'].includes(method.toUpperCase())) {
    return { 'X-CSRF-Token': current.csrf_token };
  }
  return {};
}

export function sessionExpired(): void {
  if (current?.mode === 'dev') return;
  setSessionIdentity(null);
  window.dispatchEvent(new Event('ct:session-expired'));
}
