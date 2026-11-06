// Commander view: read-only, large type, refreshes every 10 s.
import { Badge, Group, Paper, SimpleGrid, Stack, Text } from '@mantine/core';
import dayjs from 'dayjs';
import { linkLabel, rateLabel } from '../lib/linkPresentation';
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
  const restricted = status?.global_details === false;
  const audit = restricted ? null : verify;
  const link = restricted ? null : status?.link;
  const pending = restricted ? null : status?.outbox.pending;
  useInterval(() => void st.reload(), 10000);
  const s = st.data;
  return (
    <Stack gap="lg">
      <Group justify="space-between">
        <Text fz={34} fw={800}>Commander view</Text>
        <Text c="dimmed">{s ? `as of ${fmtTime(s.at)}` : ''} · refreshes every 10 s</Text>
      </Group>
      {st.error && <ErrorBox error={st.error} />}
      {restricted && <Text c="dimmed">Node-wide details are restricted. Counts cover only assets visible to your account ({status.targets} inventory assets).</Text>}
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
            <Badge size="xl" color={audit ? audit.ok ? 'green' : 'red' : 'gray'}>{restricted ? 'restricted' : audit ? (audit.ok ? 'verified' : `tampered at #${audit.bad_seq}`) : 'unknown'}</Badge>
            <Text fz={24} fw={700}>{restricted ? 'Record count restricted' : audit ? `${audit.count} records` : 'Record count unknown'}</Text>
          </Group>
          <Text fz={22} mt="xs">{restricted ? 'Head restricted' : audit ? <>head <HashText value={audit.head} /></> : 'Head unknown'}</Text>
        </Paper>
        <Paper withBorder p="lg" radius="md">
          <Text size="lg" c="dimmed" fw={700} tt="uppercase">Link</Text>
          {status ? (
            <>
              <Badge size="xl" mt="xs" color={!link ? 'gray' : link.connected ? 'teal' : 'orange'}>{restricted ? 'Link restricted' : linkLabel(link)}</Badge>
              <Text fz={24} fw={700} mt="xs">{restricted ? 'Rate restricted' : rateLabel(link)}</Text>
              <Text fz={18} c="dimmed">{restricted ? 'Queue count restricted' : pending == null ? 'Queue count unknown' : `${pending} reports queued for sync`}</Text>
              {status.kill.engaged && <Badge size="xl" color="red" mt="sm">Kill switch engaged</Badge>}
            </>
          ) : <Loading />}
        </Paper>
      </SimpleGrid>
    </Stack>
  );
}
