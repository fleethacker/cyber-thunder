import { Button, Group, NumberInput, Paper, Select, Stack, Switch, Text } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useEffect, useState } from 'react';
import { api, errorText } from '../api/client';
import type { LinkState } from '../api/types';
import { useAsync, useInterval } from '../lib/hooks';
import { linkLabel, rateLabel } from '../lib/linkPresentation';
import { useAppState } from '../state/AppState';
import { actorProblem } from './ActorChip';
import { ErrorBox, Loading } from './common';

export function LinkControls({ compact = false }: { compact?: boolean }) {
  const st = useAsync(() => api.link(), []);
  const { refresh, status, actor } = useAppState();
  const [draft, setDraft] = useState<LinkState | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { if (st.data) setDraft(st.data); }, [st.data]);
  useInterval(() => { if (st.data?.probe_enabled && !busy) void st.reload(); }, 5000);
  const blocked = busy || !!status?.kill.engaged || !!actorProblem(actor);
  const save = async (patch: Partial<LinkState>) => {
    setBusy(true); setError(null);
    try {
      const next = await api.putLink(patch);
      st.setData(next);
      notifications.show({ message: linkLabel(next) });
      await refresh();
    } catch (e) { setError(errorText(e)); }
    finally { setBusy(false); }
  };
  const probe = async () => {
    setBusy(true); setError(null);
    try { await api.probeLink(); await st.reload(); await refresh(); }
    catch (e) { setError(errorText(e)); }
    finally { setBusy(false); }
  };
  if (!draft) return st.error ? <ErrorBox error={st.error} onRetry={() => void st.reload()} /> : <Loading what="Reading link state" />;
  const dirty = st.data && (draft.kbps !== st.data.kbps || draft.latency_ms !== st.data.latency_ms);
  const noProbe = blocked || draft.offline_override || (draft.mode === 'test' && !draft.test_connected);
  return <Paper withBorder p="md" radius="md"><Stack gap="sm">
    {!compact && <Text fw={700}>Link observations and controls</Text>}
    <Text>{linkLabel(draft)} · {rateLabel(draft)}</Text>
    {draft.rate_observation && <Text size="xs">Rate observed at {draft.rate_observation.at} from {draft.rate_observation.endpoint}</Text>}
    <Text size="sm" c="dimmed">Rates use response-body bytes and request time, not physical bandwidth. Physical latency is unknown. Unknown reachability permits an explicit network attempt.</Text>
    {draft.last_observation && <Text size="xs">Last request: {draft.last_observation.at} · {draft.last_observation.endpoint} · {draft.last_observation.application_bytes} bytes / {draft.last_observation.elapsed_seconds} s · {draft.last_observation.success ? 'succeeded' : 'failed'}</Text>}
    <Switch label="Operator offline — block network attempts" checked={draft.offline_override} disabled={blocked}
      onChange={(e) => void save({ offline_override: e.currentTarget.checked })} />
    <Switch label="Enable test emulation (audited)" checked={draft.mode === 'test'} disabled={blocked}
      onChange={(e) => void save({ mode: e.currentTarget.checked ? 'test' : 'production' })} />
    {draft.mode === 'test' && <Group align="flex-end">
      <NumberInput label="Test rate (kbps)" value={draft.kbps ?? 56} min={0.1} max={1000000} disabled={blocked}
        onChange={(v) => setDraft({ ...draft, kbps: typeof v === 'number' ? v : draft.kbps })} />
      <NumberInput label="Test delay (ms)" value={draft.latency_ms ?? 500} min={0} max={60000} disabled={blocked}
        onChange={(v) => setDraft({ ...draft, latency_ms: typeof v === 'number' ? v : draft.latency_ms })} />
      <Button disabled={blocked || !dirty} onClick={() => void save({ kbps: draft.kbps, latency_ms: draft.latency_ms })}>Save test values</Button>
      <Switch label="Test connected" checked={draft.test_connected} disabled={blocked}
        onChange={(e) => void save({ connected: e.currentTarget.checked })} />
    </Group>}
    <Select label="Official endpoint for reachability probe" value={draft.probe_endpoint} disabled={blocked}
      data={['https://www.cyber.mil/', 'https://dl.dod.cyber.mil/']} onChange={(v) => { if (v) void save({ probe_endpoint: v }); }} />
    <Group>
      <Button disabled={noProbe} loading={busy} onClick={() => void probe()}>Probe once</Button>
      <Switch label="Probe every 30 seconds for 15 minutes" checked={draft.probe_enabled}
        disabled={blocked || (!draft.probe_enabled && noProbe)}
        onChange={(e) => void save({ probe_enabled: e.currentTarget.checked })} />
    </Group>
    <Text size="xs" c="dimmed">Off by default. Probes use HEAD, reject redirects and stop after five seconds. Automatic failure/recovery detection requires this temporary opt-in session. Each probe concerns only the selected endpoint.</Text>
    {error && <ErrorBox error={error} />}
  </Stack></Paper>;
}
