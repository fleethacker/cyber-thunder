// Constrained-link emulation: kbps, latency, connected toggle. Reconnecting flushes the outbox (server side).
import { Button, Group, NumberInput, Paper, Stack, Switch, Text } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useEffect, useState } from 'react';
import { api, errorText } from '../api/client';
import type { LinkState } from '../api/types';
import { useAsync } from '../lib/hooks';
import { useAppState } from '../state/AppState';
import { ErrorBox, Loading } from './common';

export function LinkControls({ compact = false }: { compact?: boolean }) {
  const st = useAsync(() => api.link(), []);
  const { refresh } = useAppState();
  const [draft, setDraft] = useState<LinkState | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => { if (st.data) setDraft(st.data); }, [st.data]);

  const save = async (patch: Partial<LinkState>) => {
    setBusy(true);
    setError(null);
    try {
      const next = await api.putLink(patch);
      st.setData(next);
      notifications.show({ message: `Link: ${next.connected ? 'connected' : 'disconnected'} at ${next.kbps} kbps, ${next.latency_ms} ms` });
      await refresh();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  if (!draft) return st.error ? <ErrorBox error={st.error} onRetry={() => void st.reload()} /> : <Loading what="Reading link state" />;
  const dirty = st.data && (draft.kbps !== st.data.kbps || draft.latency_ms !== st.data.latency_ms);
  return (
    <Paper withBorder p="md" radius="md">
      <Stack gap="sm">
        {!compact && <Text fw={700}>Link emulation</Text>}
        <Group align="flex-end" gap="sm" wrap="wrap">
          <NumberInput label="Bandwidth (kbps)" value={draft.kbps} min={0.1} step={8} w={160}
            onChange={(v) => setDraft({ ...draft, kbps: typeof v === 'number' ? v : draft.kbps })} />
          <NumberInput label="Latency (ms)" value={draft.latency_ms} min={0} step={50} w={140}
            onChange={(v) => setDraft({ ...draft, latency_ms: typeof v === 'number' ? v : draft.latency_ms })} />
          <Button disabled={!dirty} loading={busy} onClick={() => void save({ kbps: draft.kbps, latency_ms: draft.latency_ms })}>Set</Button>
          <Switch
            size="lg"
            label={draft.connected ? 'Connected' : 'Disconnected'}
            checked={draft.connected}
            onChange={(e) => void save({ connected: e.currentTarget.checked })}
            color="teal"
            mb={6}
          />
        </Group>
        {error && <ErrorBox error={error} />}
      </Stack>
    </Paper>
  );
}
