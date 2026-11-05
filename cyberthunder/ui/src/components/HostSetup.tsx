import { Alert, Badge, Button, Checkbox, Group, Modal, NumberInput, Radio, Select, Stack, Text, TextInput, Textarea } from '@mantine/core';
import { useEffect, useRef, useState } from 'react';
import { api, errorText } from '../api/client';
import type { AssetFacts, HostRegistration, RuntimeContext, Target, TargetReadiness } from '../api/types';
import { ErrorBox, JsonView, Loading } from './common';
import { useSetupAccess } from './setupAccess';

export function RuntimeBoundary({ runtime }: { runtime: RuntimeContext }) {
  return <Alert color={runtime.kind === 'native' ? 'blue' : 'orange'} title="Where the service runs">
    <Stack gap={4}>
      <Text size="sm">Runtime: {runtime.kind} · runtime OS: {runtime.runtime_os}. The physical host OS and address have not been detected.</Text>
      <Text size="sm">{runtime.local_transport.description}</Text>
      <Text size="sm">{runtime.kind === 'native'
        ? 'No known container marker was found. This is not proof of bare metal; local access stays inside this service environment.'
        : 'Local access in a container or Kubernetes deployment reaches that environment, not the physical host. Supply an authorized host address for SSH or WinRM.'}</Text>
      {runtime.hints.map((hint) => <Text size="sm" key={hint.code}>{hint.message}</Text>)}
    </Stack>
  </Alert>;
}

export function ReadinessView({ readiness }: { readiness: TargetReadiness }) {
  return <Stack gap="xs">
    <Text fw={600}>Connection declarations</Text>
    <Badge color={readiness.ready_for_connection_test ? 'blue' : 'orange'} variant="light" style={{ alignSelf: 'flex-start' }}>
      {readiness.ready_for_connection_test ? 'Declarations ready for a connection test' : 'Connection test blocked'}
    </Badge>
    <Text size="sm">Declarations only. No connection, credential, privilege or detected-OS verification has occurred.</Text>
    {readiness.checks.map((check) => <Text size="sm" key={check.code}>{check.status}: {check.message}</Text>)}
    {readiness.warnings.map((warning, i) => <Alert color="orange" key={i}>{warning}</Alert>)}
  </Stack>;
}

/** Mounted only while the user has explicitly opened host setup. */
export function HostSetupContent({ onSaved, onUseLocal, setBusy }: {
  onSaved: (target: Target) => void;
  onUseLocal: (defaults: Partial<Target>) => void;
  setBusy: (busy: boolean) => void;
}) {
  const blocked = useSetupAccess();
  const alive = useRef(true);
  const inFlight = useRef(false);
  const [runtime, setRuntime] = useState<RuntimeContext>();
  const [runtimeError, setRuntimeError] = useState<string | null>(null);
  const [runtimeRevision, setRuntimeRevision] = useState(0);
  const [platform, setPlatform] = useState<'linux' | 'windows' | ''>('');
  const [id, setId] = useState('');
  const [name, setName] = useState('');
  const [address, setAddress] = useState('');
  const [port, setPort] = useState<number | null>(null);
  const [username, setUsername] = useState('');
  const [credential, setCredential] = useState('');
  const [sudo, setSudo] = useState(false);
  const [scope, setScope] = useState('');
  const [reason, setReason] = useState('');
  const [reviewing, setReviewing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState<Target>();
  const [error, setError] = useState<string | null>(null);
  const [readiness, setReadiness] = useState<TargetReadiness>();
  const [readinessError, setReadinessError] = useState<string | null>(null);
  const [readinessRevision, setReadinessRevision] = useState(0);
  const [testing, setTesting] = useState(false);
  const [facts, setFacts] = useState<AssetFacts>();

  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  useEffect(() => {
    let active = true;
    setRuntime(undefined); setRuntimeError(null);
    void api.runtimeContext().then((value) => { if (active) setRuntime(value); })
      .catch((e) => { if (active) setRuntimeError(errorText(e)); });
    return () => { active = false; };
  }, [runtimeRevision]);
  useEffect(() => {
    if (!saved) return;
    let active = true;
    setReadiness(undefined); setReadinessError(null);
    void api.targetReadiness(saved.id).then((value) => {
      if (value.target_id !== saved.id || value.checked !== 'declarations_only') throw new Error('Readiness does not match this registered asset. Refresh declarations.');
      if (active) setReadiness(value);
    }).catch((e) => { if (active) setReadinessError(errorText(e)); });
    return () => { active = false; };
  }, [saved, readinessRevision]);

  const transport = platform === 'windows' ? 'winrm' : 'ssh';
  const ready = !!runtime && !!platform && /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(id.trim()) &&
    !!name.trim() && !!address.trim() && !!username.trim() && /^[A-Za-z0-9_.-]{1,64}$/.test(credential.trim()) &&
    (port === null || (Number.isInteger(port) && port >= 1 && port <= 65535)) && !!scope && !!reason.trim() && reason.trim().length <= 1000;
  const body = (): HostRegistration => ({
    id: id.trim(), name: name.trim(), asset_type: platform as 'linux' | 'windows', transport,
    address: address.trim(), port, username: username.trim(), credential_ref: credential.trim(),
    sudo: platform === 'linux' && sudo, in_scope: scope === 'in', reason: reason.trim(),
  });
  const register = async () => {
    if (!ready || !reviewing || blocked || saved || inFlight.current) return;
    inFlight.current = true; setSaving(true); setBusy(true); setError(null);
    try {
      const target = await api.registerHost(body());
      if (!alive.current) return;
      setSaved(target); onSaved(target);
    } catch (e) { if (alive.current) setError(errorText(e)); }
    finally { inFlight.current = false; if (alive.current) { setSaving(false); setBusy(false); } }
  };
  const canTest = !!saved?.in_scope && readiness?.target_id === saved?.id && readiness?.ready_for_connection_test === true && !readinessError && !blocked;
  const testConnection = async () => {
    if (!saved || !canTest || inFlight.current) return;
    inFlight.current = true; setTesting(true); setBusy(true); setFacts(undefined); setError(null);
    try {
      const value = await api.discover(saved.id);
      if (alive.current) setFacts(value);
    } catch (e) { if (alive.current) setError(errorText(e)); }
    finally { inFlight.current = false; if (alive.current) { setTesting(false); setBusy(false); } }
  };

  if (runtimeError) return <ErrorBox error={runtimeError} onRetry={() => setRuntimeRevision((v) => v + 1)} />;
  if (!runtime) return <Loading what="Reading service environment (no target connection)" />;
  return <Stack gap="md">
    <RuntimeBoundary runtime={runtime} />
    {blocked && <Alert color="yellow">{blocked}</Alert>}
    {saved ? <>
      <Alert color="blue" title="Host registered">
        {saved.name} ({saved.id}) is {saved.in_scope ? 'authorized for scans and approved changes' : 'recorded out of scope'}. No scan was started.
      </Alert>
      {readinessError ? <ErrorBox error={readinessError} onRetry={() => setReadinessRevision((v) => v + 1)} />
        : readiness ? <ReadinessView readiness={readiness} /> : <Loading what="Checking declarations only" />}
      <Text size="sm">A connection test contacts this registered target to read asset facts. It does not run a scan, authorize scope, install a service or change a firewall.</Text>
      {!saved.in_scope && <Text size="sm">Connection testing is unavailable while this asset is out of scope. A separate, reasoned inventory authorization is required.</Text>}
      <Button disabled={!canTest || testing} loading={testing} onClick={() => void testConnection()}>Test connection (read asset facts)</Button>
      {facts && <>
        <Text fw={600}>Connection test completed</Text>
        <Text size="sm">These facts describe this test response. They do not verify every scan/change privilege or ongoing reachability.</Text>
        <JsonView value={facts} maxHeight={220} />
      </>}
    </> : <>
      {!reviewing && <>
        <Text size="sm">Use an existing SSH or WinRM service on the intended host. Supply an address reachable from this service environment and a credential reference configured on the service. This setup does not install or reconfigure host access.</Text>
        {runtime.kind === 'native' && ['linux', 'windows'].includes(runtime.runtime_os) && <Button variant="light" disabled={!!blocked}
          onClick={() => { if (!blocked && !inFlight.current) onUseLocal({ asset_type: runtime.runtime_os as 'linux' | 'windows', transport: 'local', sudo: false }); }}>
          Register this service environment for local access
        </Button>}
        <Select label="Intended host operating system" required placeholder="Choose the host OS; it has not been detected" value={platform || null}
          data={[{ value: 'linux', label: 'Linux host via SSH' }, { value: 'windows', label: 'Windows host via WinRM' }]}
          onChange={(value) => { setPlatform(value === 'windows' ? 'windows' : value === 'linux' ? 'linux' : ''); setPort(value === 'windows' ? 5986 : 22); setSudo(false); }} />
        <Group grow>
          <TextInput label="Inventory ID" required maxLength={64} value={id} onChange={(e) => setId(e.currentTarget.value)} description="A stable alias; existing IDs are never overwritten." />
          <TextInput label="Host display name" required value={name} onChange={(e) => setName(e.currentTarget.value)} />
        </Group>
        <Group grow>
          <TextInput label="Reachable host address" required value={address} onChange={(e) => setAddress(e.currentTarget.value)} placeholder="One host IP or DNS name" description="Supplied by you; no gateway or physical host address is guessed." />
          <NumberInput label="Host port" min={1} max={65535} value={port ?? ''} onChange={(value) => setPort(typeof value === 'number' ? value : null)} />
        </Group>
        <TextInput label="Host account" required value={username} onChange={(e) => setUsername(e.currentTarget.value)} />
        <TextInput label="Credential reference name" required maxLength={64} value={credential} onChange={(e) => setCredential(e.currentTarget.value)} description="Name of CT_CRED_<ref> configured for this service. Never enter a password, token or key contents." />
        {platform === 'linux' && <Checkbox label="Declare sudo use for this host" checked={sudo} onChange={(e) => setSudo(e.currentTarget.checked)} />}
        <Radio.Group label="Host inventory authorization" required value={scope} onChange={setScope}>
          <Stack gap={4} mt="xs"><Radio value="out" label="Record only — keep out of scan/change scope" /><Radio value="in" label="Authorize scans and approved changes for this host" /></Stack>
        </Radio.Group>
        <Textarea label="Host authorization reason" required maxLength={1000} value={reason} onChange={(e) => setReason(e.currentTarget.value)} description="Owner/authorization and why this individual host is included or excluded. Audited on registration." />
        <Button disabled={!ready || !!blocked} onClick={() => { if (ready && !blocked) setReviewing(true); }}>Review host registration</Button>
      </>}
      {reviewing && <>
        <Text fw={600}>Review {name.trim()} ({id.trim()})</Text>
        <Text size="sm">Declared host OS: {platform}. Access: {transport} to {address.trim()}:{port ?? (platform === 'windows' ? 5986 : 22)} as {username.trim()}.</Text>
        <Text size="sm">Credential reference: {credential.trim()}. Sudo declared: {platform === 'linux' && sudo ? 'yes' : 'no'}.</Text>
        <Text size="sm">Inventory authorization: {scope === 'in' ? 'scans and approved changes for this host' : 'record only, out of scope'}.</Text>
        <Text size="sm" style={{ whiteSpace: 'pre-wrap' }}>Reason: {reason.trim()}</Text>
        <Alert color="orange">Connection unverified. Registration saves declarations and your scope decision only. It does not connect to the host or start a scan.</Alert>
        <Group justify="flex-end">
          <Button variant="default" disabled={saving} onClick={() => { if (!inFlight.current) setReviewing(false); }}>Edit declarations</Button>
          <Button disabled={!ready || !!blocked || saving} loading={saving} onClick={() => void register()}>Confirm host registration</Button>
        </Group>
      </>}
    </>}
    {error && <ErrorBox error={error} />}
  </Stack>;
}

export function HostSetup({ opened, onClose, onSaved, onUseLocal }: {
  opened: boolean; onClose: () => void; onSaved: (target: Target) => void; onUseLocal: (defaults: Partial<Target>) => void;
}) {
  const [busy, setBusy] = useState(false);
  const inFlight = useRef(false);
  return <Modal opened={opened} title="Set up deployment-host access" size="lg" centered
    onClose={() => { if (!inFlight.current) onClose(); }} closeOnClickOutside={!busy} closeOnEscape={!busy} withCloseButton={!busy}>
    {opened && <HostSetupContent onSaved={onSaved} onUseLocal={onUseLocal} setBusy={(value) => { inFlight.current = value; setBusy(value); }} />}
  </Modal>;
}
