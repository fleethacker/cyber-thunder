// Audit: live, newest-first timeline of the hash-chained log with auto-follow, filters, chain verify and download.
import { Alert, Badge, Button, Code, Group, Paper, ScrollArea, Stack, Switch, Table, Text, TextInput } from '@mantine/core';
import { IconDownload, IconShieldCheck } from '@tabler/icons-react';
import { Fragment, useEffect, useMemo, useState } from 'react';
import { api, errorText } from '../api/client';
import type { AuditRecord, AuditVerify } from '../api/types';
import { ErrorBox, HashText, JsonView, Loading, PageTitle } from '../components/common';
import { fmtTime } from '../lib/format';
import { useAppState, useAuditListener } from '../state/AppState';

const WINDOW = 500;

function outcomeColor(o: string): string {
  if (o === 'ok' || o === 'success') return 'green';
  if (o === 'blocked' || o === 'denied') return 'orange';
  if (o === 'error' || o === 'failed' || o === 'fail') return 'red';
  return 'gray';
}

export default function Audit() {
  const { stream, refresh } = useAppState();
  const [records, setRecords] = useState<AuditRecord[]>([]);
  const [buffer, setBuffer] = useState<AuditRecord[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [follow, setFollow] = useState(true);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [fAction, setFAction] = useState('');
  const [fActor, setFActor] = useState('');
  const [fSubject, setFSubject] = useState('');
  const [verify, setVerify] = useState<AuditVerify | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [oldest, setOldest] = useState(0);

  const loadTail = async () => {
    setError(null);
    try {
      const v = await api.auditVerify();
      const after = Math.max(0, v.count - WINDOW);
      const page = await api.audit({ after_seq: after, limit: WINDOW });
      setRecords(page.records.slice().reverse());
      setOldest(after);
      setLoaded(true);
    } catch (e) {
      setError(errorText(e));
    }
  };
  useEffect(() => { void loadTail(); }, []);

  useAuditListener((r) => {
    if (follow) setRecords((cur) => (cur.some((x) => x.seq === r.seq) ? cur : [r, ...cur]));
    else setBuffer((b) => [r, ...b]);
  });

  useEffect(() => {
    if (follow && buffer.length) {
      setRecords((cur) => [...buffer.filter((b) => !cur.some((x) => x.seq === b.seq)), ...cur]);
      setBuffer([]);
    }
  }, [follow, buffer]);

  const loadOlder = async () => {
    if (oldest <= 0) return;
    const after = Math.max(0, oldest - WINDOW);
    try {
      const page = await api.audit({ after_seq: after, limit: oldest - after });
      setRecords((cur) => [...cur, ...page.records.slice().reverse()]);
      setOldest(after);
    } catch (e) {
      setError(errorText(e));
    }
  };

  const shown = useMemo(() => records.filter((r) =>
    (!fAction || r.action.startsWith(fAction))
    && (!fActor || r.actor.toLowerCase().includes(fActor.toLowerCase()))
    && (!fSubject || (r.subject ?? '').includes(fSubject))), [records, fAction, fActor, fSubject]);

  const runVerify = async () => {
    setVerifying(true);
    try {
      setVerify(await api.auditVerify());
      await refresh();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setVerifying(false);
    }
  };

  const download = async () => {
    setDownloading(true);
    try {
      const lines: string[] = [];
      let after = 0;
      for (;;) {
        const page = await api.audit({ after_seq: after, limit: 5000 });
        if (!page.records.length) break;
        page.records.forEach((r) => lines.push(JSON.stringify(r)));
        after = page.records[page.records.length - 1].seq;
        if (after >= page.count) break;
      }
      const blob = new Blob([lines.join('\n') + '\n'], { type: 'application/x-ndjson' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'audit.jsonl';
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setDownloading(false);
    }
  };

  return (
    <Stack gap="md">
      <PageTitle
        title="Audit trail"
        subtitle={`Append-only, hash-chained. Stream: ${stream}.`}
        right={<>
          <Button leftSection={<IconShieldCheck size={16} />} loading={verifying} onClick={() => void runVerify()}>Verify chain</Button>
          <Button variant="light" leftSection={<IconDownload size={16} />} loading={downloading} onClick={() => void download()}>Download audit.jsonl</Button>
        </>}
      />
      {verify && (
        <Alert color={verify.ok ? 'green' : 'red'} title={verify.ok ? 'Chain verified' : `Chain broken at #${verify.bad_seq}`} withCloseButton onClose={() => setVerify(null)}>
          <Code block>{JSON.stringify(verify, null, 2)}</Code>
        </Alert>
      )}
      <Group gap="sm" align="flex-end" wrap="wrap">
        <TextInput label="Action (prefix)" placeholder="proposal." value={fAction} onChange={(e) => setFAction(e.currentTarget.value)} w={200} />
        <TextInput label="Actor" value={fActor} onChange={(e) => setFActor(e.currentTarget.value)} w={180} />
        <TextInput label="Subject" value={fSubject} onChange={(e) => setFSubject(e.currentTarget.value)} w={200} />
        <Switch label="Auto-follow" checked={follow} onChange={(e) => setFollow(e.currentTarget.checked)} mb={8} />
        {!follow && buffer.length > 0 && <Button size="xs" variant="light" onClick={() => setFollow(true)} mb={4}>{buffer.length} new</Button>}
      </Group>
      {error && <ErrorBox error={error} onRetry={() => void loadTail()} />}
      {!loaded ? (!error && <Loading what="Reading the audit chain" />) : shown.length === 0 ? (
        <Text c="dimmed">No audit records{records.length ? ' match these filters' : ' yet'}.</Text>
      ) : (
        <Paper withBorder radius="md">
          <ScrollArea>
            <Table highlightOnHover verticalSpacing={6} miw={900}>
              <Table.Thead>
                <Table.Tr><Table.Th>#</Table.Th><Table.Th>Time</Table.Th><Table.Th>Actor</Table.Th><Table.Th>Action</Table.Th><Table.Th>Outcome</Table.Th><Table.Th>Subject</Table.Th><Table.Th>Hash</Table.Th></Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {shown.map((r) => (
                  <Fragment key={r.seq}>
                    <Table.Tr onClick={() => setExpanded(expanded === r.seq ? null : r.seq)} style={{ cursor: 'pointer' }}>
                      <Table.Td><Text ff="monospace" size="sm">{r.seq}</Text></Table.Td>
                      <Table.Td><Text size="sm" ff="monospace">{fmtTime(r.ts)}</Text></Table.Td>
                      <Table.Td><Text size="sm">{r.actor}</Text></Table.Td>
                      <Table.Td><Text size="sm" ff="monospace">{r.action}</Text></Table.Td>
                      <Table.Td><Badge color={outcomeColor(r.outcome)} variant="light">{r.outcome}</Badge></Table.Td>
                      <Table.Td><Text size="sm" ff="monospace">{r.subject ?? '-'}</Text></Table.Td>
                      <Table.Td><HashText value={r.hash} /></Table.Td>
                    </Table.Tr>
                    {expanded === r.seq && (
                      <Table.Tr>
                        <Table.Td colSpan={7}>
                          <Stack gap={4}>
                            <Group gap="md"><Text size="xs">node {r.node}</Text><Text size="xs">prev <HashText value={r.prev_hash} n={16} /></Text><Text size="xs">hash <HashText value={r.hash} n={16} /></Text></Group>
                            <JsonView value={r.details} maxHeight={300} />
                          </Stack>
                        </Table.Td>
                      </Table.Tr>
                    )}
                  </Fragment>
                ))}
              </Table.Tbody>
            </Table>
          </ScrollArea>
          {oldest > 0 && <Group justify="center" p="sm"><Button variant="subtle" onClick={() => void loadOlder()}>Load older records</Button></Group>}
        </Paper>
      )}
    </Stack>
  );
}
