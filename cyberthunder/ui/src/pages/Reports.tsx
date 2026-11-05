// Reports: searchable saved snapshots, current reports, detection score and sync outbox.
import { Badge, Button, Card, Group, Paper, Progress, Select, SimpleGrid, Stack, Table, Text } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { IconCloudUpload, IconDownload, IconSend } from '@tabler/icons-react';
import { useState, useEffect } from 'react';
import { linkLabel } from '../lib/linkPresentation';
import { api, ApiError, errorText, url, request } from '../api/client';
import { ErrorBox, Loading, Mono, PageTitle } from '../components/common';
import { fmtBytes, fmtSeconds, fmtTime } from '../lib/format';
import { useAsync } from '../lib/hooks';
import { useAppState } from '../state/AppState';
import { ReportHistory } from '../components/ReportHistory';

function Download({ href, label, file }: { href: string; label: string; file: string }) {
  return (
    <Button component="a" href={href} download={file} variant="light" size="sm" leftSection={<IconDownload size={14} />}>{label}</Button>
  );
}

function ScoreCard() {
  const st = useAsync(async () => {
    try {
      return await api.score();
    } catch (e) {
      if (e instanceof ApiError && (e.status === 404 || e.status === 501 || e.status === 503)) return null;
      throw e;
    }
  }, []);
  return (
    <Card withBorder radius="md">
      <Stack gap="xs">
        <Group justify="space-between"><Text fw={700}>Detection score</Text><Button size="xs" variant="subtle" onClick={() => void st.reload()}>Refresh</Button></Group>
        {st.data === undefined ? (st.error ? <ErrorBox error={st.error} /> : <Loading />) : st.data === null ? (
          <Text size="sm" c="dimmed">No range answer key present (range/answer_key.json).</Text>
        ) : (
          <>
            <Group gap="md" align="baseline">
              <Text fz={36} fw={800}>{st.data.found}/{st.data.seeded}</Text>
              <Text c="dimmed">seeded issues found ({(st.data.share * 100).toFixed(0)}%)</Text>
            </Group>
            <Progress value={st.data.share * 100} color={st.data.share >= 0.8 ? 'green' : 'orange'} />
            <Table withTableBorder striped>
              <Table.Tbody>
                {st.data.items.map((i) => (
                  <Table.Tr key={i.id}>
                    <Table.Td w={90}><Badge color={i.found ? 'green' : 'red'} variant="light">{i.found ? 'found' : 'missed'}</Badge></Table.Td>
                    <Table.Td w={110}><Text size="sm">{i.kind}</Text></Table.Td>
                    <Table.Td><Text size="sm">{i.what}</Text></Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </>
        )}
      </Stack>
    </Card>
  );
}

function OutboxCard() {
  const st = useAsync(() => api.outbox(), []);
  const { refresh } = useAppState();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const sync = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await api.sync();
      notifications.show({ message: `Locally staged ${r.sent} items, ${fmtBytes(r.bytes)} in ${fmtSeconds(r.seconds)}` });
      await Promise.all([st.reload(), refresh()]);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card withBorder radius="md">
      <Stack gap="xs">
        <Group justify="space-between">
          <Group gap="xs"><Text fw={700}>Local outbox staging</Text>{st.data && <Badge color={st.data.connected ? 'teal' : 'orange'} variant="light">{linkLabel(st.data.link)}</Badge>}</Group>
          <Button size="xs" leftSection={<IconCloudUpload size={14} />} loading={busy} disabled={!st.data?.connected || !st.data?.pending.length} onClick={() => void sync()}>Stage locally</Button>
        </Group>
        {error && <ErrorBox error={error} />}
        {st.data === undefined ? (st.error ? <ErrorBox error={st.error} onRetry={() => void st.reload()} /> : <Loading />) : (
          <>
            {st.data.pending.length === 0 ? <Text size="sm" c="dimmed">Nothing queued.</Text> : (
              <Table withTableBorder striped>
                <Table.Thead><Table.Tr><Table.Th>Pending</Table.Th><Table.Th>Kind</Table.Th><Table.Th>Size</Table.Th><Table.Th>Queued</Table.Th></Table.Tr></Table.Thead>
                <Table.Tbody>
                  {st.data.pending.map((o) => (
                    <Table.Tr key={o.id ?? o.name}><Table.Td><Mono>{o.name}</Mono></Table.Td><Table.Td>{o.kind}</Table.Td><Table.Td>{fmtBytes(o.bytes)}</Table.Td><Table.Td>{fmtTime(o.created_at)}</Table.Td></Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            )}
            {st.data.synced.length > 0 && (
              <Table withTableBorder striped>
                <Table.Thead><Table.Tr><Table.Th>Staged locally</Table.Th><Table.Th>Kind</Table.Th><Table.Th>Size</Table.Th><Table.Th>Timing basis</Table.Th></Table.Tr></Table.Thead>
                <Table.Tbody>
                  {st.data.synced.slice(-10).reverse().map((o) => (
                    <Table.Tr key={o.id ?? `${o.name}-${o.synced_at}`}><Table.Td><Mono>{o.name}</Mono></Table.Td><Table.Td>{o.kind}</Table.Td><Table.Td>{fmtBytes(o.bytes)}</Table.Td><Table.Td>{o.test_estimate_seconds != null ? 'Test estimate: ' + fmtSeconds(o.test_estimate_seconds) : 'Local move; no network timing'}</Table.Td></Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            )}
          </>
        )}
      </Stack>
    </Card>
  );
}

type Doc = 'commander' | 'fleet' | 'friction' | 'coverage';
const DOC_PATH: Record<Doc, string> = { commander: '/reports/commander', fleet: '/reports/fleet', friction: '/reports/friction', coverage: '/reports/coverage' };
const DOC_LABEL: Record<Doc, string> = {
  commander: 'Commander one-pager', fleet: 'Path to fleet', friction: 'Friction log', coverage: 'Check & fix coverage',
};

export default function Reports() {
  const [doc, setDoc] = useState<Doc>('commander');
  const [host, setHost] = useState<string | null>(null);
  const [queueing, setQueueing] = useState<string | null>(null);
  const targets = useAsync(async () => (await api.targets()).targets, []);
  const [frameKey, setFrameKey] = useState(0);
  const [html, setHtml] = useState<string>('');
  useEffect(() => {
    let alive = true;
    setHtml('');
    request<string>('GET', DOC_PATH[doc], { query: { format: 'html' } })
      .then((h) => { if (alive) setHtml(h); })
      .catch((e) => { if (alive) setHtml(`<p style="font-family:sans-serif;color:#b00020;padding:16px">${errorText(e)}</p>`); });
    return () => { alive = false; };
  }, [doc, frameKey]);

  const queue = async (kind: 'commander' | 'poam' | 'checklist') => {
    setQueueing(kind);
    try {
      await api.queueReport(kind, undefined, kind === 'checklist' ? host ?? undefined : undefined);
      notifications.show({ message: `${kind} queued for sync on reconnect` });
    } catch (e) {
      notifications.show({ color: 'red', title: 'Refused', message: errorText(e) });
    } finally {
      setQueueing(null);
    }
  };

  return (
    <Stack gap="md">
      <PageTitle title="Reports" subtitle="Search past reports or generate a report from the current findings and audit trail." />
      <ReportHistory />
      <Paper withBorder radius="md" p="md">
        <Stack gap="sm">
          <Group justify="space-between" wrap="wrap">
            <Select label="Current report" value={doc} onChange={(value) => { if (value) setDoc(value as Doc); }}
              data={Object.entries(DOC_LABEL).map(([value, label]) => ({ value, label }))} allowDeselect={false} w={250} />
            <Group gap="xs">
              <Download href={url(DOC_PATH[doc], { format: 'html' })} label="HTML" file={`${doc}.html`} />
              <Download href={url(DOC_PATH[doc], { format: 'md' })} label="Markdown" file={`${doc}.md`} />
              <Button size="sm" variant="subtle" onClick={() => setFrameKey((k) => k + 1)}>{doc === 'commander' ? 'Generate report' : 'Refresh report'}</Button>
              {doc === 'commander' && (
                <Button size="sm" leftSection={<IconSend size={14} />} loading={queueing === 'commander'} onClick={() => void queue('commander')}>Queue for sync</Button>
              )}
            </Group>
          </Group>
          <iframe
            key={`${doc}-${frameKey}`}
            title={DOC_LABEL[doc]}
            srcDoc={html}
            sandbox=""
            style={{ width: '100%', height: 640, border: '1px solid var(--mantine-color-default-border)', borderRadius: 8, background: 'white' }}
          />
        </Stack>
      </Paper>

      <SimpleGrid cols={{ base: 1, md: 2 }}>
        <Card withBorder radius="md">
          <Stack gap="sm">
            <Text fw={700}>POA&amp;M</Text>
            <Text size="sm" c="dimmed">Plan of action and milestones for every open finding, as CSV.</Text>
            <Group gap="xs">
              <Download href={url('/reports/poam.csv')} label="POA&M CSV" file="poam.csv" />
              <Button size="sm" variant="subtle" leftSection={<IconSend size={14} />} loading={queueing === 'poam'} onClick={() => void queue('poam')}>Queue for sync</Button>
            </Group>
          </Stack>
        </Card>
        <Card withBorder radius="md">
          <Stack gap="sm">
            <Text fw={700}>Updated checklist (CKLB)</Text>
            <Text size="sm" c="dimmed">STIG Viewer checklist with statuses written back, per host.</Text>
            <Group gap="xs" align="flex-end">
              <Select placeholder="Host" data={(targets.data ?? []).map((t) => ({ value: t.id, label: t.name }))} value={host} onChange={setHost} w={200} />
              {host
                ? <Download href={url('/reports/checklist.cklb', { host })} label="CKLB" file={`${host}.cklb`} />
                : <Button size="sm" variant="light" disabled leftSection={<IconDownload size={14} />}>CKLB</Button>}
              <Button size="sm" variant="subtle" leftSection={<IconSend size={14} />} disabled={!host} loading={queueing === 'checklist'} onClick={() => void queue('checklist')}>Queue for sync</Button>
            </Group>
            {targets.error && <ErrorBox error={targets.error} />}
          </Stack>
        </Card>
        <ScoreCard />
        <OutboxCard />
      </SimpleGrid>
    </Stack>
  );
}
