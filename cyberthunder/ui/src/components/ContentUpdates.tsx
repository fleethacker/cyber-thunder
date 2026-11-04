// DISA content updates: what the node holds, what the inventory needs, pulls with per-file progress, and
// the manifest / import-folder path for when the link is down. Pulls are read-only downloads; see docs/CONTENT.md.
import { Alert, Badge, Button, Checkbox, Group, Paper, Progress, Stack, Switch, Table, Text, TextInput, Tooltip } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { IconCloudDownload } from '@tabler/icons-react';
import { useEffect, useState } from 'react';
import { api, errorText } from '../api/client';
import type { ContentRow, HeldContent, ImportDirResult, PullDelta, PullJob, UpdateCheck } from '../api/types';
import { fmtAgo, fmtBytes, fmtSeconds } from '../lib/format';
import { useAsync } from '../lib/hooks';
import { useAppState } from '../state/AppState';
import { ErrorBox, Loading } from './common';

const FINISHED: PullJob['state'][] = ['done', 'partial', 'failed', 'stopped'];
const STATE_COLOR: Record<string, string> = {
  done: 'teal', failed: 'red', quarantined: 'red', stopped: 'orange', pending: 'gray', downloading: 'blue',
  verifying: 'blue', retrying: 'yellow', partial: 'orange', running: 'blue', queued: 'gray',
};

function HeldTable({ held }: { held: HeldContent }) {
  if (!held.files.length) return <Text size="sm" c="dimmed">No DISA content held yet. Check for updates, or import a folder.</Text>;
  return (
    <Table striped withTableBorder fz="sm">
      <Table.Thead>
        <Table.Tr><Table.Th>Product</Table.Th><Table.Th>Kind</Table.Th><Table.Th>Version</Table.Th><Table.Th>DISA date</Table.Th><Table.Th>Source</Table.Th></Table.Tr>
      </Table.Thead>
      <Table.Tbody>
        {held.products.flatMap((g) => g.files.map((f) => (
          <Table.Tr key={f.filename}>
            <Table.Td><Tooltip label={f.filename}><Text size="sm" ff="monospace">{g.product_key}</Text></Tooltip></Table.Td>
            <Table.Td>{f.kind.replace('_', ' ')}</Table.Td>
            <Table.Td>{f.version_label ?? '-'}</Table.Td>
            <Table.Td>{f.upload_date ?? '-'}</Table.Td>
            <Table.Td>{f.source} {fmtAgo(f.fetched_at)}</Table.Td>
          </Table.Tr>
        )))}
      </Table.Tbody>
    </Table>
  );
}

function UpdatesTable({ rows, selected, toggle }: { rows: ContentRow[]; selected: Set<string>; toggle: (f: string) => void }) {
  if (!rows.length) return <Text size="sm" c="teal">Everything the inventory needs is held and current.</Text>;
  return (
    <Table withTableBorder fz="sm">
      <Table.Thead>
        <Table.Tr><Table.Th /><Table.Th>File</Table.Th><Table.Th>Version</Table.Th><Table.Th>Held</Table.Th><Table.Th>Size</Table.Th><Table.Th>For</Table.Th></Table.Tr>
      </Table.Thead>
      <Table.Tbody>
        {rows.map((r) => (
          <Table.Tr key={r.filename}>
            <Table.Td><Checkbox aria-label={`select ${r.filename}`} checked={selected.has(r.filename)} onChange={() => toggle(r.filename)} /></Table.Td>
            <Table.Td><Text size="sm" ff="monospace">{r.filename}</Text></Table.Td>
            <Table.Td>{r.version_label ?? '-'} <Text span size="xs" c="dimmed">{r.upload_date}</Text></Table.Td>
            <Table.Td>{r.held_version ? r.held_version.join('.') : 'none'}</Table.Td>
            <Table.Td>{fmtBytes(r.expected_bytes)}</Table.Td>
            <Table.Td>{(r.targets ?? []).join(', ')}</Table.Td>
          </Table.Tr>
        ))}
      </Table.Tbody>
    </Table>
  );
}

function DeltaRow({ d }: { d: PullDelta }) {
  const [busy, setBusy] = useState(false);
  const rescan = async () => {
    setBusy(true);
    try {
      const run = await api.rescanDelta(d.id);
      notifications.show({ message: `Rescan started: ${run.id}` });
    } catch (e) {
      notifications.show({ color: 'red', message: errorText(e) });
    } finally {
      setBusy(false);
    }
  };
  const c = d.counts ?? {};
  return (
    <Group gap="sm">
      <Text size="sm">{d.filename}: {d.old_release ?? '(none)'} → {d.new_release}, {c.added ?? 0} added, {c.changed ?? 0} changed, {c.removed ?? 0} removed</Text>
      <Button size="xs" variant="light" loading={busy} disabled={!d.rescan_rules} onClick={() => void rescan()}>Rescan changed rules</Button>
    </Group>
  );
}

function JobProgress({ job }: { job: PullJob }) {
  return (
    <Stack gap={6}>
      <Group gap="xs"><Text size="sm" fw={600}>Pull {job.id}</Text><Badge color={STATE_COLOR[job.state]} variant="light">{job.state}</Badge></Group>
      {job.files.map((f) => {
        const pct = f.total ? Math.min(100, (f.bytes / f.total) * 100) : f.state === 'done' ? 100 : 0;
        return (
          <Stack key={f.filename} gap={2}>
            <Group justify="space-between" gap="xs">
              <Text size="xs" ff="monospace">{f.filename}</Text>
              <Group gap={6}>
                <Text size="xs" c="dimmed">{fmtBytes(f.bytes)} / {fmtBytes(f.total)}{f.estimate_seconds ? `, about ${fmtSeconds(f.estimate_seconds)} at the link rate` : ''}</Text>
                <Badge size="xs" color={STATE_COLOR[f.state]} variant="light">{f.state}</Badge>
              </Group>
            </Group>
            <Progress value={pct} size="sm" color={STATE_COLOR[f.state]} animated={f.state === 'downloading'} />
            {f.error && <Text size="xs" c="red">{f.error}</Text>}
            {f.datastream_path && <Text size="xs" c="dimmed" ff="monospace">datastream: {f.datastream_path}</Text>}
          </Stack>
        );
      })}
      {job.deltas.map((d) => <DeltaRow key={d.id} d={d} />)}
    </Stack>
  );
}

function downloadJson(name: string, doc: unknown) {
  const blob = new Blob([JSON.stringify(doc, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(a.href);
}

export function ContentUpdates() {
  const { status } = useAppState();
  const check = useAsync(() => api.updates(), []);
  const held = useAsync(() => api.content(), []);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [job, setJob] = useState<PullJob | null>(null);
  const [pace, setPace] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [folder, setFolder] = useState('');
  const [imported, setImported] = useState<ImportDirResult | null>(null);

  const report: UpdateCheck | undefined = check.data;
  const connected = status?.link?.connected ?? report?.connected ?? true;

  useEffect(() => { setSelected(new Set((report?.updates ?? []).map((u) => u.filename))); }, [report?.checked_at]);

  // follow a running pull until it finishes
  useEffect(() => {
    if (!job || FINISHED.includes(job.state)) return;
    const t = window.setTimeout(async () => {
      try {
        const next = await api.pullJob(job.id);
        setJob(next);
        if (FINISHED.includes(next.state)) {
          void held.reload();
          void check.reload();
          notifications.show({ message: `Pull ${next.state}: ${next.files.filter((f) => f.state === 'done').length} of ${next.files.length} files` });
        }
      } catch (e) {
        setError(errorText(e));
      }
    }, 1000);
    return () => window.clearTimeout(t);
  }, [job]);

  const act = async (what: string, fn: () => Promise<void>) => {
    setBusy(what);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(null);
    }
  };

  const toggle = (f: string) => setSelected((s) => {
    const n = new Set(s);
    if (n.has(f)) n.delete(f); else n.add(f);
    return n;
  });

  const est = report?.index_estimate;
  const running = !!job && !FINISHED.includes(job.state);
  return (
    <Paper withBorder p="md" radius="md">
      <Stack gap="sm">
        <Group gap="xs"><IconCloudDownload size={18} /><Text fw={700}>Content updates</Text></Group>
        <Text size="sm" c="dimmed">
          DISA STIGs and SCAP benchmarks for the assets in the inventory. Downloads come only from www.cyber.mil and
          dl.dod.cyber.mil, are verified before use, and never change a host.
        </Text>

        <Text fw={600} size="sm">Held on this node</Text>
        {held.data ? <HeldTable held={held.data} /> : held.error ? <ErrorBox error={held.error} onRetry={() => void held.reload()} /> : <Loading what="Reading content" />}
        {held.data && held.data.quarantine.length > 0 && (
          <Alert color="red" variant="light" title="Quarantined">
            {held.data.quarantine.map((q) => <Text key={q.filename + q.quarantined_at} size="xs">{q.filename}: {q.reason}</Text>)}
          </Alert>
        )}

        <Group gap="sm" align="center">
          <Tooltip label={connected ? `Index check: about ${fmtBytes(est?.bytes)}, ${fmtSeconds(est?.seconds)} at the current link` : 'The link is down: use the manifest below'}>
            <span>
              <Button loading={busy === 'check'} disabled={!connected || running}
                onClick={() => void act('check', async () => { await api.checkUpdates('live'); await check.reload(); })}>
                Check for updates
              </Button>
            </span>
          </Tooltip>
          {!connected && <Text size="sm" c="orange">Link down: check is disabled. Write a manifest for a connected machine instead.</Text>}
          {connected && est && <Text size="xs" c="dimmed">about {fmtSeconds(est.seconds)} at {est.link.kbps} kbps</Text>}
          {report?.checked_at && <Text size="xs" c="dimmed">last check {fmtAgo(report.checked_at)} ({report.source}, {report.index_entries} entries{report.gzip ? ', gzip' : ''})</Text>}
        </Group>

        {report?.checked_at && (
          <>
            <UpdatesTable rows={report.updates} selected={selected} toggle={toggle} />
            {report.updates.length > 0 && (
              <Group gap="sm">
                <Button loading={busy === 'pull'} disabled={!connected || running || selected.size === 0}
                  onClick={() => void act('pull', async () => { setJob(await api.pullUpdates({ filenames: [...selected], pace })); })}>
                  Pull selected ({selected.size})
                </Button>
                <Switch label="Pace to the link rate" checked={pace} onChange={(e) => setPace(e.currentTarget.checked)} />
                {report.estimate_seconds_at_link ? <Text size="xs" c="dimmed">all updates: about {fmtSeconds(report.estimate_seconds_at_link)} at the link rate</Text> : null}
              </Group>
            )}
            {report.skipped.filter((s) => s.target_id).map((s) => (
              <Text key={s.target_id} size="xs" c="dimmed">{s.target_id}: {s.reason}</Text>
            ))}
          </>
        )}

        {job && <JobProgress job={job} />}

        <Text fw={600} size="sm" mt="xs">Disconnected path</Text>
        <Group gap="sm" align="flex-end">
          <Button variant="light" loading={busy === 'manifest'}
            onClick={() => void act('manifest', async () => {
              const m = await api.writeManifest();
              downloadJson('manifest.json', m);
              notifications.show({ message: `Manifest written (${m.items.length} items): ${m.path}` });
            })}>
            Download manifest
          </Button>
          <TextInput label="Import folder on this node" placeholder="E:\stig-content" value={folder}
            onChange={(e) => setFolder(e.currentTarget.value)} w={280} />
          <Button variant="light" loading={busy === 'import'} disabled={!folder.trim()}
            onClick={() => void act('import', async () => {
              const r = await api.importDir(folder.trim());
              setImported(r);
              void held.reload();
              void check.reload();
            })}>
            Import folder
          </Button>
        </Group>
        {imported && (
          <Stack gap={4}>
            <Text size="sm">Imported {imported.imported.length} file(s), verified by {imported.verified_by}.</Text>
            {imported.refused.map((r) => <Text key={r.filename} size="xs" c="red">refused {r.filename}: {r.reason}</Text>)}
            {imported.missing.map((m) => <Text key={m} size="xs" c="orange">missing from the folder: {m}</Text>)}
            {imported.deltas.map((d) => <DeltaRow key={d.id} d={d} />)}
          </Stack>
        )}
        {error && <ErrorBox error={error} />}
      </Stack>
    </Paper>
  );
}
