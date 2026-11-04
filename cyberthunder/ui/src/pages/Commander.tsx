// Commander view: read-only, large type, refreshes every 10 s.
import { Badge, Group, Paper, SimpleGrid, Stack, Text } from '@mantine/core';
import dayjs from 'dayjs';
import { api } from '../api/client';
import { ErrorBox, HashText, Loading } from '../components/common';
import { fmtTime } from '../lib/format';
import { useAsync, useInterval } from '../lib/hooks';
import { useAppState } from '../state/AppState';

interface Snapshot {
  open: { high: number; medium: number; low: number };
  intrusions: number;
  verifiedToday: number;
  pending: number;
  at: string;
}

async function snapshot(): Promise<Snapshot> {
  const [findings, hunt, proposals] = await Promise.all([
    api.findings({ status: 'open', limit: 1 }),
    api.findings({ status: 'open', source: 'hunt', limit: 1 }),
    api.proposals(),
  ]);
  const sev = findings.summary?.open_by_severity ?? {};
  const today = dayjs().startOf('day');
  const verifiedToday = proposals.proposals.filter((p) =>
    p.state === 'verified' && p.history.some((h) => h.state === 'verified' && dayjs(String(h.ts ?? h.at ?? '')).isAfter(today))).length;
  return {
    open: { high: sev.high ?? 0, medium: sev.medium ?? 0, low: sev.low ?? 0 },
    intrusions: hunt.total,
    verifiedToday,
    pending: proposals.proposals.filter((p) => p.state === 'proposed').length,
    at: new Date().toISOString(),
  };
}

function Big({ label, value, color }: { label: string; value: number | string; color?: string }) {
  return (
    <Paper withBorder p="lg" radius="md">
      <Text size="lg" c="dimmed" fw={700} tt="uppercase">{label}</Text>
      <Text fz={64} fw={800} c={color} lh={1.1}>{value}</Text>
    </Paper>
  );
}

export default function Commander() {
  const st = useAsync(snapshot, []);
  const { status, verify } = useAppState();
  useInterval(() => void st.reload(), 10000);
  const s = st.data;
  return (
    <Stack gap="lg">
      <Group justify="space-between">
        <Text fz={34} fw={800}>Commander view</Text>
        <Text c="dimmed">{s ? `as of ${fmtTime(s.at)}` : ''} · refreshes every 10 s</Text>
      </Group>
      {st.error && <ErrorBox error={st.error} />}
      {!s ? (!st.error && <Loading />) : (
        <>
          <SimpleGrid cols={{ base: 1, sm: 3 }}>
            <Big label="Open CAT I" value={s.open.high} color="red" />
            <Big label="Open CAT II" value={s.open.medium} color="orange" />
            <Big label="Open CAT III" value={s.open.low} color="blue" />
          </SimpleGrid>
          <SimpleGrid cols={{ base: 1, sm: 3 }}>
            <Big label="Intrusion indicators" value={s.intrusions} color={s.intrusions ? 'red' : 'green'} />
            <Big label="Changes verified today" value={s.verifiedToday} color="green" />
            <Big label="Decisions pending" value={s.pending} color={s.pending ? 'yellow' : undefined} />
          </SimpleGrid>
        </>
      )}
      <SimpleGrid cols={{ base: 1, sm: 2 }}>
        <Paper withBorder p="lg" radius="md">
          <Text size="lg" c="dimmed" fw={700} tt="uppercase">Audit trail</Text>
          <Group gap="sm" mt="xs">
            <Badge size="xl" color={verify?.ok ? 'green' : 'red'}>{verify ? (verify.ok ? 'verified' : `tampered at #${verify.bad_seq}`) : 'checking'}</Badge>
            <Text fz={24} fw={700}>{verify?.count ?? '-'} records</Text>
          </Group>
          <Text fz={22} mt="xs">head <HashText value={verify?.head} /></Text>
        </Paper>
        <Paper withBorder p="lg" radius="md">
          <Text size="lg" c="dimmed" fw={700} tt="uppercase">Link</Text>
          {status ? (
            <>
              <Badge size="xl" mt="xs" color={status.link.connected ? 'teal' : 'orange'}>{status.link.connected ? 'connected' : 'disconnected'}</Badge>
              <Text fz={24} fw={700} mt="xs">{status.link.kbps} kbps · {status.link.latency_ms} ms</Text>
              <Text fz={18} c="dimmed">{status.outbox.pending} reports queued for sync</Text>
              {status.kill.engaged && <Badge size="xl" color="red" mt="sm">Kill switch engaged</Badge>}
            </>
          ) : <Loading />}
        </Paper>
      </SimpleGrid>
    </Stack>
  );
}
