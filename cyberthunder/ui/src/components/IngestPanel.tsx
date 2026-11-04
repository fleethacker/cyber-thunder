// Ingest over the constrained link: drop a STIG release -> delta summary -> rescan changed rules;
// drop an IAVM bulletin -> affected hosts and new findings.
import { Badge, Button, FileButton, Group, Paper, SimpleGrid, Stack, Table, Text } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { IconFileUpload, IconRadar } from '@tabler/icons-react';
import { useState, type DragEvent, type ReactNode } from 'react';
import { api, errorText } from '../api/client';
import type { BulletinResult, DeltaReport, ScanRun } from '../api/types';
import { fmtBytes, fmtSeconds } from '../lib/format';
import { ErrorBox, Mono, SeverityBadge } from './common';

function DropZone({ label, accept, busy, onFile, children }: { label: string; accept: string; busy: boolean; onFile: (f: File) => void; children?: ReactNode }) {
  const [over, setOver] = useState(false);
  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setOver(false);
    const f = e.dataTransfer.files?.[0];
    if (f) onFile(f);
  };
  return (
    <Paper
      withBorder
      p="lg"
      radius="md"
      onDragOver={(e) => { e.preventDefault(); setOver(true); }}
      onDragLeave={() => setOver(false)}
      onDrop={onDrop}
      style={{ borderStyle: 'dashed', borderWidth: 2, borderColor: over ? 'var(--mantine-color-blue-5)' : undefined }}
    >
      <Stack align="center" gap="xs">
        <IconFileUpload size={28} opacity={0.6} />
        <Text fw={600}>{label}</Text>
        {children}
        <FileButton onChange={(f) => f && onFile(f)} accept={accept}>
          {(props) => <Button {...props} variant="light" loading={busy}>Choose file</Button>}
        </FileButton>
      </Stack>
    </Paper>
  );
}

function RuleTable({ title, rows }: { title: string; rows: DeltaReport['rules_added'] }) {
  if (!rows.length) return null;
  return (
    <Stack gap={4}>
      <Text size="sm" fw={700}>{title} ({rows.length})</Text>
      <Table withTableBorder striped>
        <Table.Tbody>
          {rows.slice(0, 50).map((r) => (
            <Table.Tr key={r.rule_id}>
              <Table.Td w={90}><SeverityBadge severity={r.severity} size="xs" /></Table.Td>
              <Table.Td w={160}><Mono>{r.stig_id ?? r.rule_id}</Mono></Table.Td>
              <Table.Td><Text size="sm">{r.title}</Text>{r.change && <Text size="xs" c="dimmed">{r.change}</Text>}</Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
      {rows.length > 50 && <Text size="xs" c="dimmed">and {rows.length - 50} more</Text>}
    </Stack>
  );
}

function Stat({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <Paper withBorder p="sm" radius="md">
      <Text size="xs" c="dimmed" tt="uppercase" fw={700}>{label}</Text>
      <Text fz={22} fw={700}>{value}</Text>
      {sub && <Text size="xs" c="dimmed">{sub}</Text>}
    </Paper>
  );
}

export function DeltaSummary({ d, onRescan }: { d: DeltaReport; onRescan: (run: ScanRun) => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const rescan = async () => {
    setBusy(true);
    setError(null);
    try {
      const run = await api.rescanDelta(d.id);
      notifications.show({ message: `Targeted rescan ${run.id} started on ${d.rescan_rule_ids.length} rules` });
      onRescan(run);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Paper withBorder p="md" radius="md">
      <Stack gap="sm">
        <Group justify="space-between">
          <Stack gap={0}>
            <Text fw={700}>{d.benchmark_id}</Text>
            <Text size="sm" c="dimmed">{d.old_release ?? '(none)'} → {d.new_release ?? '?'}</Text>
          </Stack>
          <Group gap="xs">
            <Badge color="green" variant="light">+{d.rules_added.length} added</Badge>
            <Badge color="red" variant="light">-{d.rules_removed.length} removed</Badge>
            <Badge color="orange" variant="light">{d.rules_changed.length} changed</Badge>
          </Group>
        </Group>
        <SimpleGrid cols={{ base: 2, md: 4 }}>
          <Stat label="Full release" value={fmtBytes(d.sizes.full_bytes)} sub={`${fmtSeconds(d.transfer.full_s)} at ${d.transfer.kbps} kbps`} />
          <Stat label="Delta" value={fmtBytes(d.sizes.delta_bytes)} />
          <Stat label="Compressed delta" value={fmtBytes(d.sizes.compressed_bytes)} sub={`${fmtSeconds(d.transfer.delta_s)} at ${d.transfer.kbps} kbps`} />
          <Stat label="Sent vs full" value={d.sizes.full_bytes ? `${((d.sizes.compressed_bytes / d.sizes.full_bytes) * 100).toFixed(1)}%` : '-'} sub="compressed delta / full release" />
        </SimpleGrid>
        <RuleTable title="Added" rows={d.rules_added} />
        <RuleTable title="Changed" rows={d.rules_changed} />
        <RuleTable title="Removed" rows={d.rules_removed} />
        {error && <ErrorBox error={error} />}
        <Button leftSection={<IconRadar size={16} />} disabled={!d.rescan_rule_ids.length} loading={busy} onClick={() => void rescan()} style={{ alignSelf: 'flex-start' }}>
          Rescan changed rules ({d.rescan_rule_ids.length})
        </Button>
      </Stack>
    </Paper>
  );
}

function BulletinSummary({ b }: { b: BulletinResult }) {
  return (
    <Paper withBorder p="md" radius="md">
      <Stack gap="xs">
        <Group gap="xs"><Text fw={700}>Bulletin</Text><Mono>{b.bulletin_id}</Mono></Group>
        <Text size="sm">{b.hosts_affected.length ? `Affected hosts: ${b.hosts_affected.join(', ')}` : 'No host in the latest package inventory is affected.'}</Text>
        {b.findings.length > 0 && (
          <Table withTableBorder striped>
            <Table.Tbody>
              {b.findings.map((f) => (
                <Table.Tr key={f.id}>
                  <Table.Td w={90}><SeverityBadge severity={f.severity} size="xs" /></Table.Td>
                  <Table.Td w={140}><Text size="sm">{f.host}</Text></Table.Td>
                  <Table.Td><Text size="sm">{f.title}</Text></Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
      </Stack>
    </Paper>
  );
}

export function IngestPanel({ onScan }: { onScan: (run: ScanRun) => void }) {
  const [delta, setDelta] = useState<DeltaReport | null>(null);
  const [bulletin, setBulletin] = useState<BulletinResult | null>(null);
  const [busy, setBusy] = useState<'stig' | 'bulletin' | null>(null);
  const [error, setError] = useState<string | null>(null);

  const upload = async (kind: 'stig' | 'bulletin', f: File) => {
    setBusy(kind);
    setError(null);
    try {
      if (kind === 'stig') setDelta(await api.ingestStig(f));
      else {
        const b = await api.ingestBulletin(f);
        setBulletin(b);
        notifications.show({ message: `${b.findings.length} new findings on ${b.hosts_affected.length} hosts` });
      }
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(null);
    }
  };

  return (
    <Stack gap="sm">
      <Text fw={700} size="lg">Ingest</Text>
      <SimpleGrid cols={{ base: 1, md: 2 }}>
        <DropZone label="Drop a STIG release (XCCDF xml or DISA zip)" accept=".xml,.zip" busy={busy === 'stig'} onFile={(f) => void upload('stig', f)} />
        <DropZone label="Drop a vulnerability bulletin (IAVM JSON)" accept=".json,application/json" busy={busy === 'bulletin'} onFile={(f) => void upload('bulletin', f)} />
      </SimpleGrid>
      {error && <ErrorBox error={error} />}
      {delta && <DeltaSummary d={delta} onRescan={onScan} />}
      {bulletin && <BulletinSummary b={bulletin} />}
    </Stack>
  );
}
