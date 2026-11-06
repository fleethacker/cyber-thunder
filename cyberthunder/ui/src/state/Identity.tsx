import { Alert, Badge, Button, Card, Group, Loader, Stack, Text, Title } from '@mantine/core';
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { sessionHeaders, setSessionIdentity, type SessionIdentity } from '../api/identity';

interface IdentityContext {
  identity: SessionIdentity;
  can: (action: string) => boolean;
  logout: () => Promise<void>;
}

const Context = createContext<IdentityContext | null>(null);

export function IdentityProvider({ identity, logout, children }: {
  identity: SessionIdentity; logout: () => Promise<void>; children: ReactNode;
}) {
  return <Context.Provider value={{ identity, logout,
    can: (action) => identity.mode === 'dev' || identity.permissions.includes(action) }}>
    {children}
  </Context.Provider>;
}

export function IdentityBoundary({ children }: { children: ReactNode }) {
  const [identity, setIdentity] = useState<SessionIdentity | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const generation = useRef(0);
  const refresh = useCallback(async () => {
    const version = ++generation.current;
    setBusy(true);
    try {
      const response = await fetch('/auth/status', { credentials: 'same-origin', cache: 'no-store' });
      if (!response.ok) throw new Error('Sign-in status is unavailable. Retry when the server is reachable.');
      const value = await response.json() as SessionIdentity;
      if (!['dev', 'oidc', 'mesh'].includes(value.mode) || typeof value.authenticated !== 'boolean'
          || !Array.isArray(value.permissions) || (value.authenticated && (!value.principal
            || typeof value.principal.actor !== 'string' || typeof value.principal.name !== 'string'
            || !Array.isArray(value.principal.roles)))) throw new Error('Sign-in status could not be verified.');
      if (version !== generation.current) return;
      setSessionIdentity(value);
      setIdentity(value);
      setError(null);
    } catch (e) {
      if (version !== generation.current) return;
      setSessionIdentity(null);
      setIdentity(null);
      setError((e as Error).message);
    } finally { if (version === generation.current) setBusy(false); }
  }, []);

  useEffect(() => {
    void refresh();
    const expire = () => { setIdentity(null); void refresh(); };
    window.addEventListener('ct:session-expired', expire);
    return () => { generation.current++; window.removeEventListener('ct:session-expired', expire); };
  }, [refresh]);

  useEffect(() => {
    if (!identity?.authenticated) return;
    const id = window.setInterval(() => void refresh(), 60000);
    return () => window.clearInterval(id);
  }, [identity?.authenticated, refresh]);

  const logout = async () => {
    generation.current++;
    const response = await fetch('/auth/logout', { method: 'POST', credentials: 'same-origin',
      headers: sessionHeaders('POST') });
    if (!response.ok) { setError('Sign-out failed. Retry to close this application session.'); return; }
    setSessionIdentity(null);
    setIdentity(null);
    await refresh();
  };

  if (identity && (identity.mode === 'dev' || identity.authenticated)) {
    return <IdentityProvider identity={identity} logout={logout}>
      {children}
    </IdentityProvider>;
  }
  return <Card withBorder maw={520} mx="auto" mt="xl" p="xl">
    <Stack>
      <Title order={2}>Cyber Thunder</Title>
      <Text>Sign in with your organization account to see the systems and actions assigned to you.</Text>
      {error && <Alert color="red">{error}</Alert>}
      {busy && <Loader size="sm" aria-label="Checking sign-in" />}
      {identity && !identity.login_available && <Text c="dimmed">Browser sign-in is not configured on this node. An administrator must configure its identity provider.</Text>}
      <Group>
        {identity?.login_available && <Button component="a" href="/auth/login">Sign in</Button>}
        <Button variant="default" onClick={() => void refresh()} disabled={busy}>Retry</Button>
      </Group>
      <Badge variant="light">Access follows your account permissions</Badge>
    </Stack>
  </Card>;
}

export function useIdentity(): IdentityContext {
  const value = useContext(Context);
  if (!value) throw new Error('Identity context unavailable');
  return value;
}
