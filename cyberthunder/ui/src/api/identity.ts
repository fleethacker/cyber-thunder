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
