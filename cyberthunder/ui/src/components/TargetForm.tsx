// Add / edit an inventory target. Fields shown depend on the asset type. Credentials are never stored:
// credential_ref names an environment variable (CT_CRED_<ref>) or key file the transport resolves.
import { Button, Group, Modal, NumberInput, Select, Stack, Switch, TagsInput, Text, TextInput, Textarea } from '@mantine/core';
import { useEffect, useState } from 'react';
import { api, errorText } from '../api/client';
import { ASSET_TYPES, TRANSPORTS, type Target } from '../api/types';

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

export function TargetForm({ opened, initial, onClose, onSaved }: { opened: boolean; initial: Target | null; onClose: () => void; onSaved: (t: Target) => void }) {
  const [d, setD] = useState<Draft>({ options: {} });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const editing = !!initial;

  useEffect(() => {
    if (!opened) return;
    setError(null);
    setD(initial ? { ...initial, options: { ...initial.options } } : { asset_type: 'linux', transport: 'ssh', sudo: true, in_scope: true, tags: [], options: {} });
  }, [opened, initial]);

  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setD((x) => ({ ...x, [k]: v }));
  const setOpt = (k: string, v: string) => setD((x) => ({ ...x, options: { ...x.options, [k]: v || undefined } }));
  const type = d.asset_type ?? 'linux';

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      const body: Partial<Target> = {
        id: d.id?.trim(), name: d.name?.trim() || d.id?.trim(), asset_type: d.asset_type, transport: d.transport,
        address: d.address || null, port: d.port ?? null, username: d.username || null, credential_ref: d.credential_ref || null,
        sudo: !!d.sudo, tags: d.tags ?? [], notes: d.notes ?? '',
        options: Object.fromEntries(Object.entries(d.options).filter(([, v]) => v !== undefined && v !== '')),
      };
      if (!editing) body.in_scope = d.in_scope ?? true;
      const t = editing ? await api.updateTarget(initial!.id, body) : await api.addTarget(body);
      onSaved(t);
      onClose();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal opened={opened} onClose={onClose} title={<Text fw={700}>{editing ? `Edit ${initial?.name}` : 'Add asset'}</Text>} size="lg" centered>
      <form onSubmit={(e) => { e.preventDefault(); void save(); }}>
        <Stack gap="sm">
          <Group grow>
            <TextInput label="ID" required disabled={editing} value={d.id ?? ''} onChange={(e) => set('id', e.currentTarget.value)} placeholder="rhel9-web01" />
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
          {(OPTION_FIELDS[type] ?? []).map((o) => (
            <TextInput key={o.key} label={o.label} description={o.hint} value={String(d.options[o.key] ?? '')} onChange={(e) => setOpt(o.key, e.currentTarget.value)} />
          ))}
          <TagsInput label="Tags" value={d.tags ?? []} onChange={(v) => set('tags', v)} />
          <Textarea label="Notes" value={d.notes ?? ''} onChange={(e) => set('notes', e.currentTarget.value)} autosize minRows={2} />
          {!editing && <Switch label="In scope (the agent may scan and, with approval, change it)" checked={d.in_scope ?? true} onChange={(e) => set('in_scope', e.currentTarget.checked)} />}
          {error && <Text c="red" size="sm" ff="monospace">{error}</Text>}
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>Cancel</Button>
            <Button type="submit" loading={busy} disabled={!d.id?.trim()}>{editing ? 'Save' : 'Add'}</Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}
