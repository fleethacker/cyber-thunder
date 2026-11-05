// Scans: start a scan, watch runs (progress, per-target status and errors), ingest panel, link controls.
import { Accordion, Badge, Button, Checkbox, Group, MultiSelect, Paper, Progress, Stack, Table, Text } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { IconPlayerPlay } from '@tabler/icons-react';
import { useState } from 'react';
import { api, errorText } from '../api/client';
import type { ScanRun } from '../api/types';
import { AsyncView, Empty, ErrorBox, Mono, PageTitle } from '../components/common';
import { IngestPanel } from '../components/IngestPanel';
import { LinkControls } from '../components/LinkControls';
import { fmtAgo, fmtTime } from '../lib/format';
import { useAsync, useInterval } from '../lib/hooks';
import { useAuditListener } from '../state/AppState';

const RUNNING = new Set(['pending', 'running']);

function statusColor(s: string): string {
  return { done: 'green', running: 'yellow', pending: 'gray', error: 'red', skipped: 'gray', cancelled: 'dark' }[s] ?? 'gray';
}

function RunRow({ run }: { run: ScanRun }) {
  const pct = run.progress.total ? (run.progress.done / run.progress.total) * 100 : 0;
  const running = RUNNING.has(run.status);
  return (
    <Accordion.Item value={run.id}>
      <Accordion.Control>
        <Group justify="space-between" wrap="nowrap" pr="sm">
          <Group gap="sm" wrap="nowrap">
            <Badge color={statusColor(run.status)} variant="light">{run.status}</Badge>
            <Mono>{run.id}</Mono>
            <Badge variant="outline" color="gray">{run.trigger}</Badge>
            <Text size="sm" c="dimmed">{run.modules.join(' + ')}{run.rule_filter ? ` · ${run.rule_filter.length} rules` : ''}</Text>
          </Group>
          <Group gap="sm" wrap="nowrap" w={320}>
            <Progress value={pct} animated={running} striped={running} w={140} color={run.status === 'error' ? 'red' : 'blue'} />
            <Text size="sm" w={50}>{run.progress.done}/{run.progress.total}</Text>
            <Text size="sm" c="dimmed">{fmtAgo(run.started_at)}</Text>
          </Group>
        </Group>
      </Accordion.Control>
      <Accordion.Panel>
        <Stack gap="xs">
          <Text size="sm">Requested by {run.requested_by} · started {fmtTime(run.started_at)}{run.finished_at ? ` · finished ${fmtTime(run.finished_at)}` : ''} · {run.findings_count} findings</Text>
          {run.error && <ErrorBox error={run.error} />}
          <Table withTableBorder striped>
            <Table.Thead><Table.Tr><Table.Th>Target</Table.Th><Table.Th>Status</Table.Th><Table.Th>Findings</Table.Th><Table.Th>Open</Table.Th><Table.Th>Errors</Table.Th></Table.Tr></Table.Thead>
            <Table.Tbody>
              {run.targets.map((tid) => {
                const r = run.results[tid];
                return (
                  <Table.Tr key={tid}>
                    <Table.Td><Mono>{tid}</Mono></Table.Td>
                    <Table.Td><Badge color={statusColor(r?.status ?? 'pending')} variant="light">{r?.status ?? 'pending'}</Badge></Table.Td>
                    <Table.Td>{r?.findings ?? '-'}</Table.Td>
                    <Table.Td>{r?.open ?? '-'}</Table.Td>
                    <Table.Td>{r?.errors.length ? <Text size="xs" c="red" ff="monospace" style={{ whiteSpace: 'pre-wrap' }}>{r.errors.join('\n')}</Text> : '-'}</Table.Td>
                  </Table.Tr>
                );
              })}
            </Table.Tbody>
          </Table>
        </Stack>
      </Accordion.Panel>
    </Accordion.Item>
  );
}

export default function Scans() {
  const runs = useAsync(async () => (await api.scans()).scans, []);
  const targets = useAsync(async () => (await api.targets()).targets, []);
  const [sel, setSel] = useState<string[]>([]);
  const [modules, setModules] = useState<string[]>(['check', 'hunt', 'cve']);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [openRuns, setOpenRuns] = useState<string[]>([]);

  const anyRunning = (runs.data ?? []).some((r) => RUNNING.has(r.status));
  useInterval(() => void runs.reload(), 1500, anyRunning);
  useAuditListener((r) => { if (r.action.startsWith('scan.')) void runs.reload(); });

  const added = (run: ScanRun) => {
    runs.setData((cur) => [run, ...(cur ?? []).filter((x) => x.id !== run.id)]);
    setOpenRuns((o) => [run.id, ...o]);
  };

  const start = async () => {
    setStarting(true);
    setError(null);
    try {
      const run = await api.startScan({ target_ids: sel.length ? sel : undefined, modules });
      notifications.show({ message: `Scan ${run.id} started on ${run.targets.length} targets` });
      added(run);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setStarting(false);
    }
  };

  const inScope = (targets.data ?? []).filter((t) => t.in_scope);
  return (
    <Stack gap="lg">
      <PageTitle title="Scans" subtitle="Deterministic checks find; the model only explains." />
      <Paper withBorder p="md" radius="md">
        <Stack gap="sm">
          <Text fw={700}>Start a scan</Text>
          <Group align="flex-end" gap="md" wrap="wrap">
            <MultiSelect
              label="Targets"
              placeholder={inScope.length ? 'All in-scope targets' : 'No in-scope targets'}
              data={inScope.map((t) => ({ value: t.id, label: `${t.name} (${t.asset_type})` }))}
              value={sel}
              onChange={setSel}
              clearable
              searchable
              w={360}
            />
            <Checkbox.Group label="Modules" value={modules} onChange={setModules}>
              <Group gap="md" mt={6}>
                <Checkbox value="check" label="STIG check" />
                <Checkbox value="hunt" label="Intrusion hunt" />
                <Checkbox value="cve" label="CVE match" />
              </Group>
            </Checkbox.Group>
            <Button size="md" leftSection={<IconPlayerPlay size={18} />} loading={starting} disabled={!modules.length} onClick={() => void start()}>Start scan</Button>
          </Group>
          {targets.error && <ErrorBox error={targets.error} />}
          {error && <ErrorBox error={error} />}
        </Stack>
      </Paper>

      <Stack gap="sm">
        <Text fw={700} size="lg">Runs</Text>
        <AsyncView state={runs} what="Loading scan runs" isEmpty={(d) => d.length === 0} empty={<Empty title="No scans yet">Start one above.</Empty>}>
          {(d) => (
            <Accordion multiple variant="separated" value={openRuns} onChange={setOpenRuns}>
              {d.map((r) => <RunRow key={r.id} run={r} />)}
            </Accordion>
          )}
        </AsyncView>
      </Stack>

      <IngestPanel />
      <LinkControls />
    </Stack>
  );
}
