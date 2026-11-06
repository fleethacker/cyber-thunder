import { Alert, Badge, Button, Card, Group, Loader, Modal, Stack, Text, Title } from '@mantine/core';
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { sessionHeaders, setSessionIdentity, authorityKey, parseStepUpChallenge, type SessionIdentity, type StepUpChallenge } from '../api/identity';
import { PermissionProvider } from '../components/PermissionGate';

interface IdentityContext {
  identity: SessionIdentity;
  can: (action: string) => boolean;
  logout: () => Promise<void>;
}

const Context = createContext<IdentityContext | null>(null);

export function IdentityProvider({ identity, logout, children }: {
  identity: SessionIdentity; logout: () => Promise<void>; children: ReactNode;
}) {
  const can = (action: string) => identity.mode === 'dev' || identity.permissions.includes(action);
  return <Context.Provider value={{ identity, logout, can }}>
    <PermissionProvider can={can}>{children}</PermissionProvider>
  </Context.Provider>;
}

export function IdentityBoundary({ children }: { children: ReactNode }) {
  const [identity, setIdentity] = useState<SessionIdentity | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const generation = useRef(0);
  const [challenge, setChallenge] = useState<StepUpChallenge | null>(null);
  const [reauthError, setReauthError] = useState<string | null>(null);
  const [reauthBusy, setReauthBusy] = useState(false);
  const reauthPending = useRef<number | null>(null);
  const reauthGeneration = useRef(0);
  const authority = useRef(authorityKey(null));
  const acceptIdentity = useCallback((value: SessionIdentity | null) => {
    const next = authorityKey(value);
    if (next !== authority.current) {
      authority.current = next;
      reauthGeneration.current++;
      reauthPending.current = null;
      setReauthBusy(false); setReauthError(null); setChallenge(null);
    }
    setSessionIdentity(value);
    setIdentity(value);
  }, []);
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
      acceptIdentity(value);
      setError(null);
    } catch (e) {
      if (version !== generation.current) return;
      acceptIdentity(null);
      setError((e as Error).message);
    } finally { if (version === generation.current) setBusy(false); }
  }, [acceptIdentity]);

  useEffect(() => {
    void refresh();
    const expire = () => { acceptIdentity(null); void refresh(); };
    const stepUp = (event: Event) => {
      const value = parseStepUpChallenge({ error: 'insufficient_user_authentication', step_up: (event as CustomEvent).detail });
      if (value) { setChallenge(value); setReauthError(null); }
    };
    window.addEventListener('ct:session-expired', expire);
    window.addEventListener('ct:step-up', stepUp);
    return () => { generation.current++; reauthGeneration.current++; window.removeEventListener('ct:session-expired', expire); window.removeEventListener('ct:step-up', stepUp); };
  }, [refresh, acceptIdentity]);

  useEffect(() => {
    if (!identity?.authenticated) return;
    const id = window.setInterval(() => void refresh(), 60000);
    return () => window.clearInterval(id);
  }, [identity?.authenticated, refresh]);

  const logout = async () => {
    const previousAuthority = authority.current;
    generation.current++;
    reauthGeneration.current++;
    setReauthBusy(false);
    const response = await fetch('/auth/logout', { method: 'POST', credentials: 'same-origin',
      headers: sessionHeaders('POST') });
    if (previousAuthority !== authority.current) return;
    if (!response.ok) { setError('Sign-out failed. Retry to close this application session.'); return; }
    acceptIdentity(null);
    await refresh();
  };

  const reauthenticate = async () => {
    if (reauthPending.current !== null || !identity?.authenticated || !identity.login_available || !challenge?.acr_values.length) return;
    const version = ++reauthGeneration.current;
    reauthPending.current = version; setReauthBusy(true); setReauthError(null);
    try {
      const returnTo = window.location.pathname + window.location.search + window.location.hash;
      const response = await fetch('/auth/reauthenticate', { method: 'POST', credentials: 'same-origin', cache: 'no-store',
        headers: { ...sessionHeaders('POST'), 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ return_to: returnTo }) });
      if (!response.ok) throw new Error();
      const body = await response.json();
      if (version !== reauthGeneration.current) return;
      if (typeof body.authorization_url !== 'string' || body.authorization_url.length > 8192) throw new Error();
      const destination = new URL(body.authorization_url);
      if (destination.protocol !== 'https:' || destination.username || destination.password || destination.hash) throw new Error();
      window.location.assign(destination.href);
    } catch {
      if (version === reauthGeneration.current) setReauthError('Reauthentication could not be started. Refresh sign-in and try again.');
    } finally {
      if (reauthPending.current === version) reauthPending.current = null;
      if (version === reauthGeneration.current) setReauthBusy(false);
    }
  };

  if (identity && (identity.mode === 'dev' || identity.authenticated)) {
    return <IdentityProvider key={authorityKey(identity)} identity={identity} logout={logout}>
      {children}
      <Modal opened={!!challenge} onClose={() => { if (!reauthBusy) setChallenge(null); }} title="Reauthenticate before deciding"
        closeOnClickOutside={!reauthBusy} closeOnEscape={!reauthBusy}>
        <Stack>
          <Text>This request was refused. Sign in again, then review and submit the decision yourself. No action will be repeated automatically.</Text>
          <Text size="sm">The server requires an accepted authentication context and a sign-in no more than {challenge?.max_age} seconds old.</Text>
          {!challenge?.acr_values.length && <Alert color="yellow">Accepted authentication contexts are not configured. An administrator must configure the node before this action can proceed.</Alert>}
          {!identity.login_available && <Alert color="yellow">Browser sign-in is unavailable. Obtain fresh authentication through your configured identity client.</Alert>}
          {reauthError && <Alert color="red">{reauthError}</Alert>}
          <Group>
            <Button onClick={() => void reauthenticate()} loading={reauthBusy} disabled={!identity.login_available || !challenge?.acr_values.length}>Reauthenticate</Button>
            <Button variant="default" disabled={reauthBusy} onClick={() => setChallenge(null)}>Keep reviewing</Button>
          </Group>
        </Stack>
      </Modal>
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
