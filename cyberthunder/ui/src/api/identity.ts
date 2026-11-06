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

export function sessionIdentity(): SessionIdentity | null { return current; }

export function setSessionIdentity(identity: SessionIdentity | null): void {
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
  current = null;
  window.dispatchEvent(new Event('ct:session-expired'));
}
