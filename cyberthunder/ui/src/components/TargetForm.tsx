// Add / edit an inventory target. Fields shown depend on the asset type. Credentials are never stored:
// credential_ref names an environment variable (CT_CRED_<ref>) or key file the transport resolves.
import { Alert, Button, Group, Modal, NumberInput, Radio, Select, Stack, Switch, TagsInput, Text, TextInput, Textarea } from '@mantine/core';
import { useEffect, useRef, useState } from 'react';
import { api, errorText } from '../api/client';
import { ASSET_TYPES, TRANSPORTS, type Target } from '../api/types';
import { useSetupAccess } from './setupAccess';

type Draft = Partial<Target> & { options: Record<string, unknown> };

const DEFAULT_TRANSPORT: Record<string, string> = {
  linux: 'ssh', windows: 'winrm', cisco_ios: 'ssh', kubernetes: 'kubeconfig', containers: 'ssh',
};

const OPTION_FIELDS: Record<string, { key: string; label: string; hint: string }[]> = {
  linux: [{ key: 'critical_services', label: 'Critical services (comma separated)', hint: 'checked after every change' }],
  windows: [{ key: 'critical_services', label: 'Critical services (comma separated)', hint: 'checked after every change' }],
  cisco_ios: [{ key: 'config_path', label: 'Running-config file (file transport)', hint: 'path to a saved show running-config' }],
  kubernetes: [{ key: 'kubeconfig', label: 'Kubeconfig path', hint: 'read-only context for discovery and checks' }, { key: 'namespace', label: 'Namespace', hint: 'empty = all' }],
  containers: [{ key: 'runtime', label: 'Runtime', hint: 'docker or podman' }],
};

export function TargetForm({ opened, initial, defaults, onClose, onSaved }: { opened: boolean; initial: Target | null; defaults?: Partial<Target>; onClose: () => void; onSaved: (t: Target) => void }) {
  const [d, setD] = useState<Draft>({ options: {} });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scope, setScope] = useState('');
  const [reason, setReason] = useState('');
  const [reviewing, setReviewing] = useState(false);
  const inFlight = useRef(false);
  const blocked = useSetupAccess();
  const editing = !!initial;

  useEffect(() => {
    if (!opened) return;
    setError(null);
    setScope(''); setReason(''); setReviewing(false);
    setD(initial ? { ...initial, options: { ...initial.options } } : { asset_type: 'linux', transport: 'ssh', sudo: true, tags: [], ...defaults, options: { ...defaults?.options } });
  }, [opened, initial, defaults]);

  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setD((x) => ({ ...x, [k]: v }));
  const setOpt = (k: string, v: string) => setD((x) => ({ ...x, options: { ...x.options, [k]: v || undefined } }));
  const type = d.asset_type ?? 'linux';
  const ready = !!d.id?.trim() && (editing || (!!scope && !!reason.trim()));

  const save = async () => {
    if (!opened || inFlight.current || blocked || !ready || (!editing && !reviewing)) return;
    inFlight.current = true;
    setBusy(true);
    setError(null);
    try {
      const body: Partial<Target> = {
        id: d.id?.trim(), name: d.name?.trim() || d.id?.trim(), asset_type: d.asset_type, transport: d.transport,
        address: d.address || null, port: d.port ?? null, username: d.username || null, credential_ref: d.credential_ref || null,
        sudo: !!d.sudo, tags: d.tags ?? [], notes: d.notes ?? '',
        options: Object.fromEntries(Object.entries(d.options).filter(([, v]) => v !== undefined && v !== '')),
      };
      if (!editing) {
        body.in_scope = scope === 'in';
        body.notes = [body.notes, `Registration scope ${scope === 'in' ? 'authorized' : 'not authorized'}: ${reason.trim()}`].filter(Boolean).join('\n');
      }
      const t = editing ? await api.updateTarget(initial!.id, body) : await api.addTarget(body);
      onSaved(t);
      onClose();
    } catch (e) {
      setError(errorText(e));
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  };

  return (
    <Modal opened={opened} onClose={() => { if (!inFlight.current) onClose(); }} closeOnClickOutside={!busy} closeOnEscape={!busy} withCloseButton={!busy}
      title={<Text fw={700}>{editing ? `Edit ${initial?.name}` : reviewing ? 'Review asset registration' : 'Add asset'}</Text>} size="lg" centered>
      <form onSubmit={(e) => { e.preventDefault(); if (blocked || !ready || inFlight.current) return; if (!editing && !reviewing) setReviewing(true); else void save(); }}>
        <Stack gap="sm">
          {!reviewing && <>
          <Group grow>
            <TextInput label="ID" required disabled={editing || busy} value={d.id ?? ''} onChange={(e) => set('id', e.currentTarget.value)} placeholder="rhel9-web01" />
            <TextInput label="Name" value={d.name ?? ''} onChange={(e) => set('name', e.currentTarget.value)} />
          </Group>
          <Group grow>
            <Select label="Asset type" data={ASSET_TYPES} value={type} allowDeselect={false}
              onChange={(v) => setD((x) => ({ ...x, asset_type: (v ?? 'linux') as Target['asset_type'], transport: editing ? x.transport : DEFAULT_TRANSPORT[v ?? 'linux'] }))} />
            <Select label="Transport" data={[...TRANSPORTS]} value={d.transport ?? 'ssh'} allowDeselect={false} onChange={(v) => set('transport', v ?? 'ssh')} />
          </Group>
          {type !== 'kubernetes' && (
            <Group grow>
              <TextInput label="Address" value={d.address ?? ''} onChange={(e) => set('address', e.currentTarget.value)} placeholder="10.10.0.21" />
              <NumberInput label="Port" value={d.port ?? ''} onChange={(v) => set('port', typeof v === 'number' ? v : null)} min={1} max={65535} />
            </Group>
          )}
          {type !== 'kubernetes' && (
            <Group grow>
              <TextInput label="Username" value={d.username ?? ''} onChange={(e) => set('username', e.currentTarget.value)} />
              <TextInput label="Credential reference" description="env var CT_CRED_<ref> or key file path; never the secret itself"
                value={d.credential_ref ?? ''} onChange={(e) => set('credential_ref', e.currentTarget.value)} />
            </Group>
          )}
          {type === 'linux' && <Switch label="Use sudo" checked={!!d.sudo} onChange={(e) => set('sudo', e.currentTarget.checked)} />}
          {d.transport === 'local' && <Alert color="orange">Local runs inside the service process environment. If the service is in a container, local means that container, not its physical host. Use guided host setup for deployment-host access.</Alert>}
          {(OPTION_FIELDS[type] ?? []).map((o) => (
            <TextInput key={o.key} label={o.label} description={o.hint} value={String(d.options[o.key] ?? '')} onChange={(e) => setOpt(o.key, e.currentTarget.value)} />
          ))}
          <TagsInput label="Tags" value={d.tags ?? []} onChange={(v) => set('tags', v)} />
          <Textarea label="Notes" value={d.notes ?? ''} onChange={(e) => set('notes', e.currentTarget.value)} autosize minRows={2} />
          {!editing && <>
            <Radio.Group label="Inventory authorization" required value={scope} onChange={setScope} description="Choose explicitly. A discovery search range does not authorize this asset.">
              <Stack gap={4} mt="xs"><Radio value="out" label="Record only — keep out of scan/change scope" /><Radio value="in" label="Authorize scans and approved changes for this asset" /></Stack>
            </Radio.Group>
            <Textarea label="Authorization reason" required value={reason} onChange={(e) => setReason(e.currentTarget.value)} description="Who owns this asset and why it is included or excluded; recorded with registration." />
          </>}
          </>}
          {reviewing && <>
            <Text fw={600}>{d.name?.trim() || d.id} ({d.id})</Text>
            <Text size="sm">{d.asset_type} via {d.transport} · {d.transport === 'local' ? 'service execution environment' : d.address || 'address not declared'}{d.port ? `:${d.port}` : ''}</Text>
            {d.transport === 'local' && <Text size="sm">Local access stays inside the service environment. A container-local target is not its physical deployment host.</Text>}
            <Text size="sm">Inventory authorization: {scope === 'in' ? 'scans and approved changes' : 'record only, out of scope'}.</Text>
            <Text size="sm" style={{ whiteSpace: 'pre-wrap' }}>Reason: {reason.trim()}</Text>
            <Alert color="blue">These are connection declarations. Reachability, credentials and privileges have not been verified. Registering this asset does not start a scan.</Alert>
          </>}
          {blocked && <Alert color="yellow">{blocked}</Alert>}
          {error && <Text c="red" size="sm" ff="monospace">{error}</Text>}
          <Group justify="flex-end">
            {reviewing && <Button variant="default" disabled={busy} onClick={() => { if (!inFlight.current) setReviewing(false); }}>Back to declarations</Button>}
            <Button variant="default" disabled={busy} onClick={() => { if (!inFlight.current) onClose(); }}>Cancel</Button>
            <Button type="submit" loading={busy} disabled={busy || !!blocked || !ready}>{editing ? 'Save' : reviewing ? 'Confirm registration' : 'Review registration'}</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}
