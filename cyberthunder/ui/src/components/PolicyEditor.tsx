// Standing approval policy editor. Default is off. Enabling needs a reason and is signed by the current
// actor (server sets signed_by/signed_at). "Evaluate against current queue" previews what would auto-approve.
import { Alert, Badge, Card, Checkbox, Group, MultiSelect, Select, Stack, Switch, Table, TagsInput, Text, TextInput } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { IconPlus, IconTrash } from '@tabler/icons-react';
import { useEffect, useState } from 'react';
import { api, errorText } from '../api/client';
import { ASSET_TYPES, type AutomationPolicy, type PolicyDecision, type PolicyRule, type ProposalPlus } from '../api/types';
import { fmtTime } from '../lib/format';
import { useAsync } from '../lib/hooks';
import { useAppState } from '../state/AppState';
import { PermissionButton, PermissionConfirm, PermissionGate, usePermissions } from './PermissionGate';
import { ErrorBox, Loading, SeverityBadge } from './common';

const NEW_RULE: PolicyRule = {
  name: 'low-risk config', asset_types: [], max_disruption: 'low', allow_reboot: false, allow_patch: false, allow_service_restart: false,
  fix_allowlist: [], target_allowlist: [], max_severity: null, window_start: null, window_end: null,
};

function RuleEditor({ rule, onChange, onRemove }: { rule: PolicyRule; onChange: (r: PolicyRule) => void; onRemove: () => void }) {
  const set = <K extends keyof PolicyRule>(k: K, v: PolicyRule[K]) => onChange({ ...rule, [k]: v });
  return (
    <Card withBorder radius="md" padding="sm">
      <Stack gap="xs">
        <Group justify="space-between">
          <TextInput label="Rule name" value={rule.name} onChange={(e) => set('name', e.currentTarget.value)} w={260} />
          <PermissionButton action="policy" size="xs" color="red" variant="subtle" leftSection={<IconTrash size={14} />} onClick={onRemove}>Remove rule</PermissionButton>
        </Group>
        <Group gap="sm" wrap="wrap" align="flex-end">
          <MultiSelect label="Asset types (empty = any)" data={ASSET_TYPES} value={rule.asset_types} onChange={(v) => set('asset_types', v)} w={260} clearable />
          <Select label="Max disruption" data={['low', 'medium', 'high']} value={rule.max_disruption} allowDeselect={false} onChange={(v) => set('max_disruption', (v ?? 'low') as PolicyRule['max_disruption'])} w={140} />
          <Select label="Max severity" data={[{ value: 'any', label: 'any' }, { value: 'low', label: 'CAT III' }, { value: 'medium', label: 'CAT II' }, { value: 'high', label: 'CAT I' }]}
            value={rule.max_severity ?? 'any'} allowDeselect={false} onChange={(v) => set('max_severity', !v || v === 'any' ? null : (v as PolicyRule['max_severity']))} w={140} />
          <TextInput label="Window start" placeholder="HH:MM" value={rule.window_start ?? ''} onChange={(e) => set('window_start', e.currentTarget.value || null)} w={110} />
          <TextInput label="Window end" placeholder="HH:MM" value={rule.window_end ?? ''} onChange={(e) => set('window_end', e.currentTarget.value || null)} w={110} />
        </Group>
        <Group gap="lg">
          <Checkbox label="Allow reboot" checked={rule.allow_reboot} onChange={(e) => set('allow_reboot', e.currentTarget.checked)} />
          <Checkbox label="Allow patch" checked={rule.allow_patch} onChange={(e) => set('allow_patch', e.currentTarget.checked)} />
          <Checkbox label="Allow service restart" checked={rule.allow_service_restart} onChange={(e) => set('allow_service_restart', e.currentTarget.checked)} />
        </Group>
        <Group grow>
          <TagsInput label="Fix allowlist (fix refs or rule ids; empty = any)" value={rule.fix_allowlist} onChange={(v) => set('fix_allowlist', v)} />
          <TagsInput label="Target allowlist (target ids; empty = any in scope)" value={rule.target_allowlist} onChange={(v) => set('target_allowlist', v)} />
        </Group>
      </Stack>
    </Card>
  );
}

export function PolicyEditor() {
  const st = useAsync(() => api.policy(), []);
  const permission = usePermissions();
  const { actor, refresh } = useAppState();
  const [rules, setRules] = useState<PolicyRule[]>([]);
  const [confirm, setConfirm] = useState<'enable' | 'disable' | 'save' | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<{ p: ProposalPlus; d: PolicyDecision }[] | null>(null);
  const [previewing, setPreviewing] = useState(false);

  useEffect(() => { if (st.data) setRules(st.data.rules.map((r) => ({ ...NEW_RULE, ...r }))); }, [st.data]);

  const put = async (enabled: boolean, reason: string) => {
    if (!permission.can('policy') || busy) return;
    setBusy(true);
    setError(null);
    try {
      const p: AutomationPolicy = await api.putPolicy({ enabled, reason: reason || null, rules });
      st.setData(p);
      setConfirm(null);
      notifications.show({ message: p.enabled ? `Standing approval enabled, signed by ${p.signed_by}` : 'Standing approval saved (off: a human approves every change)' });
      await refresh();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const evaluate = async () => {
    if (!permission.can('read') || previewing) return;
    setPreviewing(true);
    setError(null);
    try {
      const queue = (await api.proposals({ state: 'proposed' })).proposals;
      if (!permission.can('read')) return;
      const out = await Promise.all(queue.map(async (p) => ({ p, d: await api.evaluatePolicy(p.id) })));
      setPreview(out);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setPreviewing(false);
    }
  };

  if (!st.data) return st.error ? <ErrorBox error={st.error} onRetry={() => void st.reload()} /> : <Loading what="Loading policy" />;
  const pol = st.data;
  return (
    <Stack gap="sm">
      <Group justify="space-between">
        <Group gap="xs">
          <Text fw={700} size="lg">Standing approval policy</Text>
          <Badge color={pol.enabled ? 'cyan' : 'gray'} variant={pol.enabled ? 'filled' : 'light'}>{pol.enabled ? 'enabled' : 'off'}</Badge>
          <Text size="xs" c="dimmed">v{pol.version}</Text>
        </Group>
        <PermissionGate allowed={permission.can('policy')} reason={permission.reason('policy') || ''}><Switch
          size="lg"
          label={pol.enabled ? 'Enabled' : 'Off'}
          checked={pol.enabled}
          onChange={() => { if (permission.can('policy')) { setError(null); setConfirm(pol.enabled ? 'disable' : 'enable'); } }}
          color="cyan"
        /></PermissionGate>
      </Group>
      <Alert color={pol.enabled ? 'cyan' : 'gray'} variant="light">
        {pol.enabled
          ? `Signed by ${pol.signed_by} at ${fmtTime(pol.signed_at)}: "${pol.reason ?? ''}". Matching fixes are approved on their behalf and recorded as policy:${pol.signed_by}. Applying still respects the kill switch.`
          : 'Off: a human approves every change. A policy is a signed statement by a named person that narrow, low-risk fixes may be approved on their behalf.'}
      </Alert>
      {!permission.can('policy') && <Alert color="yellow">{permission.reason('policy')} Saved rules and queue evaluation remain available.</Alert>}
      <fieldset disabled={!permission.can('policy') || busy} style={{ border: 0, padding: 0, margin: 0 }}>
      {rules.map((r, i) => (
        <RuleEditor key={i} rule={r} onChange={(nr) => setRules(rules.map((x, j) => (j === i ? nr : x)))} onRemove={() => setRules(rules.filter((_, j) => j !== i))} />
      ))}
      </fieldset>
      <Group gap="sm">
        <PermissionButton action="policy" variant="light" leftSection={<IconPlus size={14} />} onClick={() => { if (permission.can('policy')) setRules([...rules, { ...NEW_RULE, name: `rule ${rules.length + 1}` }]); }}>Add rule</PermissionButton>
        <PermissionButton action="policy" variant="light" onClick={() => { if (permission.can('policy')) { setError(null); setConfirm('save'); } }}>Save rules</PermissionButton>
        <PermissionButton action="read" variant="subtle" loading={previewing} onClick={() => void evaluate()}>Evaluate against current queue</PermissionButton>
      </Group>
      {error && <ErrorBox error={error} />}
      {preview && (
        preview.length === 0 ? <Text size="sm" c="dimmed">No proposals are waiting.</Text> : (
          <Table withTableBorder striped>
            <Table.Thead><Table.Tr><Table.Th>CAT</Table.Th><Table.Th>Proposal</Table.Th><Table.Th>Host</Table.Th><Table.Th>Eligible</Table.Th><Table.Th>Why</Table.Th></Table.Tr></Table.Thead>
            <Table.Tbody>
              {preview.map(({ p, d }) => (
                <Table.Tr key={p.id}>
                  <Table.Td><SeverityBadge severity={p.severity} size="xs" /></Table.Td>
                  <Table.Td><Text size="sm">{p.title}</Text></Table.Td>
                  <Table.Td><Text size="sm">{p.target?.name ?? p.host}</Text></Table.Td>
                  <Table.Td><Badge color={d.auto_eligible ? 'cyan' : 'gray'} variant="light">{d.auto_eligible ? `yes: ${d.rule}` : 'no'}</Badge></Table.Td>
                  <Table.Td><Text size="xs">{d.reasons.join('; ') || '-'}</Text></Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )
      )}
      <Text size="xs" c="dimmed">Evaluation uses the saved policy; save rule changes first.</Text>
      <PermissionConfirm action="policy"
        opened={!!confirm}
        onClose={() => setConfirm(null)}
        title={confirm === 'enable' ? 'Enable standing approval' : confirm === 'disable' ? 'Turn standing approval off' : 'Save policy rules'}
        body={confirm === 'enable'
          ? `You (${actor || 'set your name first'}) are signing a standing approval: fixes matching these ${rules.length} rule(s) will be approved on your behalf.`
          : confirm === 'disable' ? 'Every change will need a human approval again.' : `Save ${rules.length} rule(s). The policy stays ${pol.enabled ? 'enabled (re-signed by you)' : 'off'}.`}
        reasonRequired={confirm === 'enable' || (confirm === 'save' && pol.enabled)}
        confirmLabel={confirm === 'enable' ? 'Sign and enable' : confirm === 'disable' ? 'Turn off' : 'Save'}
        confirmColor={confirm === 'enable' ? 'cyan' : 'blue'}
        busy={busy}
        error={error}
        onConfirm={(reason) => void put(confirm === 'enable' ? true : confirm === 'disable' ? false : pol.enabled, reason)}
      />
    </Stack>
  );
}
