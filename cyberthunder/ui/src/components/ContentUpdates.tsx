import { Accordion, Alert, Badge, Button, Checkbox, FileInput, Group, Paper, Progress, Stack, Switch, Table, Text, TextInput } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useEffect, useRef, useState } from 'react';
import { linkLabel } from '../lib/linkPresentation';
import { canOverrideContent, contentAccount, contentProvenance, manifestText, plainUploadNeedsException } from '../lib/contentAuthenticity';
import { usePermissions } from './PermissionGate';
import { api, errorText } from '../api/client';
import type { ContentUploadResult, ImportDirResult, PullDelta, PullJob, StigLibrary } from '../api/types';
import { fmtBytes, fmtSeconds, fmtZonedTime } from '../lib/format';
import { useAppState } from '../state/AppState';
import { actorProblem } from './ActorChip';
import { DisplayedSelection, FileProvenance, LibraryTable, kindLabel } from './LibraryTables';
import { ErrorBox } from './common';

const STATE_COLOR: Record<string, string> = {
  done: 'teal', failed: 'red', quarantined: 'red', stopped: 'orange', pending: 'gray', downloading: 'blue',
  verifying: 'blue', retrying: 'yellow', partial: 'orange', running: 'blue', queued: 'gray',
};
export const jobRunning = (job: PullJob) => job.state === 'running' || job.state === 'queued';

function DeltaRow({ d }: { d: PullDelta }) {
  const { status, actor } = useAppState();
  const [busy, setBusy] = useState(false);
  const rescan = async () => {
    setBusy(true);
    try {
      const run = await api.rescanDelta(d.id);
      notifications.show({ message: `Rescan started: ${run.id}` });
    } catch (e) {
      notifications.show({ color: 'red', message: errorText(e) });
    } finally { setBusy(false); }
  };
  const c = d.counts ?? {};
  return <Paper withBorder p="sm" radius="md">
    <Group gap="sm" justify="space-between">
      <Stack gap={2} style={{ minWidth: 0 }}>
        <Text size="sm" style={{ overflowWrap: 'anywhere' }}>{d.filename}</Text>
        <Text size="xs" c="dimmed">{d.old_release ?? '(none)'} → {d.new_release ?? 'Unknown release'} · {c.added ?? 0} added, {c.changed ?? 0} changed, {c.removed ?? 0} removed</Text>
      </Stack>
      <Button size="xs" variant="light" loading={busy} disabled={!d.rescan_rules || !status || status.kill.engaged || !!actorProblem(actor)} onClick={() => void rescan()}>Rescan changed rules</Button>
    </Group>
  </Paper>;
}

function JobProgress({ job }: { job: PullJob }) {
  return <Stack gap="sm">
    <Text size="xs" c="dimmed">Started {fmtZonedTime(job.created_at)} by {job.created_by}{job.finished_at ? ` · Finished ${fmtZonedTime(job.finished_at)}` : ''}</Text>
    {job.error && <ErrorBox error={job.error} />}
    <LibraryTable rows={job.files} label="transfer files" searchText={(f) => `${f.filename} ${f.state}`} empty="This transfer has no files."
      headings={<><Table.Th>File</Table.Th><Table.Th>Progress</Table.Th><Table.Th>State</Table.Th></>}
      render={(f) => {
        const pct = f.total ? Math.min(100, (f.bytes / f.total) * 100) : f.state === 'done' ? 100 : 0;
        return <Table.Tr key={f.filename}>
          <Table.Td><Text size="xs" style={{ overflowWrap: 'anywhere' }}>{f.filename}</Text>
            {f.error && <Text size="xs" c="red">{f.error}</Text>}
            {f.datastream_path && <Text size="xs" c="dimmed" style={{ overflowWrap: 'anywhere' }}>Datastream: {f.datastream_path}</Text>}</Table.Td>
          <Table.Td miw={160}><Progress value={pct} size="sm" color={STATE_COLOR[f.state]} animated={f.state === 'downloading'} aria-label={`${f.filename} transfer progress`} />
            <Text size="xs" mt={4}>{fmtBytes(f.bytes)} / {fmtBytes(f.total)}</Text>
            {!!f.estimate_seconds && <Text size="xs" c="dimmed">Test estimate: {fmtSeconds(f.estimate_seconds)} at the configured test rate</Text>}</Table.Td>
          <Table.Td><Badge size="xs" color={STATE_COLOR[f.state]} variant="light">{f.state}</Badge></Table.Td>
        </Table.Tr>;
      }} />
    {job.deltas.map((d) => <DeltaRow key={d.id} d={d} />)}
  </Stack>;
}

function downloadJson(name: string, contents: string) {
  const blob = new Blob([contents], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

interface UploadItem { file: File; state: 'queued' | 'uploading' | 'done' | 'failed'; result?: ContentUploadResult; error?: string }

export function ContentUpdates({ library, dirty, disabled, onRefresh, view = 'all', onProductSelect, onMaintained, onTransfers }: {
  library: StigLibrary; dirty: boolean; disabled: boolean; onRefresh: () => Promise<void>;
  view?: 'all' | 'updates' | 'transfers'; onProductSelect?: (key: string) => void; onMaintained?: () => void; onTransfers?: () => void;
}) {
  const { status } = useAppState();
  const permission = usePermissions();
  const account = contentAccount();
  const ownerRef = useRef({ account });
  if (ownerRef.current.account !== account) ownerRef.current = { account };
  const owner = ownerRef.current;
  const sameAccount = () => ownerRef.current === owner && account === contentAccount();
  const [override, setOverride] = useState(false);
  const [overrideReason, setOverrideReason] = useState('');
  const [overrideAccount, setOverrideAccount] = useState<string | null>(null);
  const exception = useRef({ override, reason: overrideReason, account: overrideAccount });
  exception.current = { override, reason: overrideReason, account: overrideAccount };
  const [selected, setSelected] = useState<string[]>([]);
  const [pace, setPace] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [folder, setFolder] = useState('');
  const [imported, setImported] = useState<ImportDirResult | null>(null);
  const [files, setFiles] = useState<File[]>([]);
  const [uploads, setUploads] = useState<UploadItem[]>([]);
  const [newJob, setNewJob] = useState<PullJob | null>(null);
  const [openJobs, setOpenJobs] = useState<string[]>([]);
  const updates = library.selection.updates;
  const updateKey = JSON.stringify(updates.map((r) => r.filename).sort());
  const jobs = newJob && !library.jobs.some((j) => j.id === newJob.id) ? [newJob, ...library.jobs].slice(0, 20) : library.jobs;
  const running = jobs.some(jobRunning);
  const runningIds = JSON.stringify(jobs.filter(jobRunning).map((job) => job.id));
  const link = status?.global_details === false ? null : status?.link;
  const connected = link === null ? null : link?.connected ?? library.connected;
  const blocked = disabled || !!busy;
  const exceptionBlocked = override && (overrideAccount !== contentAccount() || !canOverrideContent() || !overrideReason.trim() || overrideReason.trim().length > 512);
  const importBlocked = blocked || !permission.can('import') || exceptionBlocked;
  const selectionBlocked = blocked || dirty || running;
  const gates = useRef({ disabled, busy: !!busy, dirty, running, connected });
  gates.current = { disabled, busy: !!busy, dirty, running, connected };
  const importNotices = imported ? [
    ...imported.refused.map((r) => ({ ...r, state: 'Refused' })),
    ...imported.skipped.map((r) => ({ ...r, state: 'Skipped' })),
    ...imported.missing.map((filename) => ({ filename, reason: 'Missing from the folder', state: 'Missing' })),
  ] : [];

  useEffect(() => { setSelected([]); }, [updateKey]);
  useEffect(() => {
    setSelected([]); setFiles([]); setFolder(''); setOverride(false); setOverrideReason('');
    setOverrideAccount(null); setUploads([]); setImported(null); setNewJob(null); setError(null);
  }, [account]);
  useEffect(() => { setOpenJobs((current) => [...new Set([...current, ...JSON.parse(runningIds) as string[]])]); }, [runningIds]);
  // Resume newly started jobs even if the first library refresh failed.
  useEffect(() => {
    if (!newJob || !jobRunning(newJob) || library.jobs.some((j) => j.id === newJob.id)) return;
    const timer = window.setTimeout(async () => {
      if (!sameAccount()) return;
      try {
        const result = await api.pullJob(newJob.id);
        if (!sameAccount()) return;
        setNewJob(result); await onRefresh();
      } catch (e) { if (sameAccount()) { setError(errorText(e)); setNewJob({ ...newJob }); } }
    }, 1500);
    return () => window.clearTimeout(timer);
  }, [newJob, library.jobs, onRefresh, account]);

  const requireAction = (action: string) => {
    if (!sameAccount() || gates.current.disabled || !permission.can(action)) {
      throw new Error('Content operation stopped: account or permissions changed. Refresh the library before retrying.');
    }
  };
  const act = async (what: string, fn: () => Promise<void>) => {
    const gate = gates.current;
    if (!sameAccount() || gate.disabled || gate.busy || (['pull', 'manifest'].includes(what) && (gate.dirty || gate.running)) || (what === 'pull' && !gate.connected)) return;
    if (!permission.can(what === 'manifest' ? 'export' : what === 'pull' ? 'admin' : 'import')) return;
    gate.busy = true;
    setBusy(what);
    setError(null);
    try { await fn(); }
    catch (e) { if (sameAccount()) setError(errorText(e)); }
    finally { gates.current.busy = false; setBusy(null); }
  };
  const importException = (value = exception.current, plain = false) => {
    requireAction('import');
    if (!value.override) {
      if (plain && plainUploadNeedsException()) throw new Error('A plain upload requires an explicit human exception. Use folder import for an attested bundle.');
      return undefined;
    }
    if (value.account !== account || !canOverrideContent() || !value.reason.trim() || value.reason.trim().length > 512) {
      throw new Error('This exception requires a verified human with import and admin permissions and a reason.');
    }
    return value.reason.trim();
  };
  const upload = async () => {
    // One explicit exception applies to this batch; recheck the account and roles for every file.
    const intent = { ...exception.current };
    importException(intent, true);
    const batch: UploadItem[] = files.map((file) => ({ file, state: 'queued' }));
    setUploads(batch);
    for (let i = 0; i < batch.length; i++) {
      const item = batch[i];
      const reason = importException(intent, true);
      try {
        if (!/\.(xml|zip)$/i.test(item.file.name)) throw new Error('Choose an XML or ZIP file.');
        if (item.file.size > 32 * 1024 * 1024) throw new Error('File exceeds the 32 MiB upload limit.');
        batch[i] = { ...item, state: 'uploading' };
        setUploads([...batch]);
        const result = await api.uploadContent(item.file, reason);
        if (!sameAccount()) return;
        requireAction('import');
        batch[i] = { ...item, state: 'done', result };
        setUploads([...batch]);
        await onRefresh().catch((e) => { if (sameAccount()) setError(`File imported, but the library could not refresh: ${errorText(e)}`); });
      } catch (e) {
        if (!sameAccount()) return;
        batch[i] = { ...item, state: 'failed', error: errorText(e) };
        setUploads([...batch]);
      }
    }
    if (sameAccount()) setFiles(batch.filter((item) => item.state === 'failed').map((item) => item.file));
  };

  return <Stack gap="lg">
    {dirty && <Alert color="yellow" title="Unsaved maintenance selections">Save or discard changes in Maintained or Browse all before checking, downloading, or writing a manifest.</Alert>}
    {error && <ErrorBox error={error} />}
    {view !== 'transfers' && <>
    <Paper withBorder p="md" radius="md">
      <Stack gap="sm">
        <Group justify="space-between"><Text fw={700}>Downloads for maintained products ({updates.length})</Text><Badge variant="light" color={connected === null ? 'gray' : connected ? 'teal' : 'orange'}>{status?.global_details === false ? 'Link restricted' : linkLabel(link)}</Badge></Group>
        <Text size="sm" c="dimmed">New releases and missing downloads for saved products and content types, compared with the {library.catalog.source === 'snapshot' ? 'snapshot' : 'last live index'}. Select files explicitly to download. A listed update does not establish scanner readiness.</Text>
        <Group>{onMaintained && <Button variant="light" onClick={onMaintained}>Change maintained products</Button>}{onTransfers && <Button variant="light" onClick={onTransfers}>Import or view transfers{running ? ' · active' : ''}</Button>}</Group>
        <LibraryTable rows={updates} label="matching updates" empty={library.selection.wanted.length ? 'No newer or missing releases are listed for your saved selections. This does not establish freshness beyond the index shown above.' : 'No files match your saved selections. Choose products and content types in Maintained.'}
          searchText={(r) => `${r.filename} ${r.product_key} ${r.version_label} ${kindLabel(r.kind)}`}
          toolbar={(displayed) => <DisplayedSelection displayed={displayed} selected={selected} keyOf={(r) => r.filename} onChange={setSelected} disabled={selectionBlocked} />}
          headings={<><Table.Th>Download</Table.Th><Table.Th>File</Table.Th><Table.Th>Listed / local version</Table.Th><Table.Th>Publisher date</Table.Th><Table.Th>Size</Table.Th></>}
          render={(r) => <Table.Tr key={r.filename}>
            <Table.Td><Checkbox aria-label={`Download ${r.filename}`} checked={selected.includes(r.filename)} disabled={selectionBlocked} onChange={(e) => setSelected(e.currentTarget.checked ? [...selected, r.filename] : selected.filter((name) => name !== r.filename))} /></Table.Td>
            <Table.Td><Text size="xs" style={{ overflowWrap: 'anywhere' }}>{r.filename}</Text><Text size="xs" c="dimmed">{kindLabel(r.kind)}{r.targets?.length ? ` · ${r.targets.join(', ')}` : ''}</Text>
              {r.product_key && onProductSelect && <Button variant="subtle" size="compact-xs" onClick={() => onProductSelect(r.product_key!)}>Product versions and maintenance</Button>}</Table.Td>
            <Table.Td>{r.version_label ?? 'Not provided'}<Text size="xs" c="dimmed">Local: {r.held_version?.join('.') ?? 'none'}</Text></Table.Td>
            <Table.Td>{fmtZonedTime(r.upload_date, 'Not provided')}</Table.Td><Table.Td>{fmtBytes(r.expected_bytes)}</Table.Td>
          </Table.Tr>} />
        <Group>
          <Button loading={busy === 'pull'} disabled={selectionBlocked || !permission.can('admin') || !connected || !selected.length} onClick={() => void act('pull', async () => {
            const result = await api.pullUpdates({ filenames: selected.filter((name) => updates.some((r) => r.filename === name)), pace: pace && link?.mode === 'test' });
            requireAction('admin');
            setNewJob(result);
            onTransfers?.();
            await onRefresh();
          })}>Download selected ({selected.length})</Button>
          <Switch label="Pace downloads to the configured TEST rate" checked={pace && link?.mode === 'test'} disabled={blocked || link?.mode !== 'test'} onChange={(e) => setPace(e.currentTarget.checked)} />
        </Group>
        {!permission.can('admin') && <Text size="sm" c="dimmed">Downloading updates requires the admin permission and a node grant.</Text>}
        {!connected && <Text size="sm" c={connected === null ? 'dimmed' : 'orange'}>{connected === null
          ? 'Link status is restricted or unknown. Download availability cannot be determined.' : 'Use a manifest and local import while disconnected.'}</Text>}
        {library.selection.skipped.length > 0 && <Accordion variant="contained"><Accordion.Item value="skipped"><Accordion.Control>Unmatched or skipped ({library.selection.skipped.length})</Accordion.Control><Accordion.Panel>
          <LibraryTable rows={library.selection.skipped} label="skipped entries" empty="No skipped entries." searchText={(s) => `${s.target_id} ${s.filename} ${s.product_key} ${s.reason}`}
            headings={<><Table.Th>Item</Table.Th><Table.Th>Reason</Table.Th></>}
            render={(s, i) => <Table.Tr key={i}><Table.Td>{s.target_id ?? s.product_key ?? s.filename ?? 'Selection'}</Table.Td><Table.Td>{s.reason}</Table.Td></Table.Tr>} />
        </Accordion.Panel></Accordion.Item></Accordion>}
      </Stack>
    </Paper>
    </>}
    {view !== 'updates' && <>
    <Alert color="blue" title="Offline content trust">
      <Text size="sm">Verified nodes require an operator-attested bundle. Configure trusted keys on the server, then use folder import. A plain XML or ZIP has no attestation.</Text>
      <Checkbox mt="sm" label="Request an exception for unsigned content or an unknown signer" checked={override}
        disabled={blocked || (!override && !canOverrideContent())} onChange={(event) => {
          if (sameAccount() && (!event.currentTarget.checked || canOverrideContent())) {
            setOverride(event.currentTarget.checked);
            setOverrideAccount(event.currentTarget.checked ? contentAccount() : null);
          }
        }} />
      {!canOverrideContent() && <Text size="xs">Exceptions require a verified human with import and admin permissions. The server also checks node grants.</Text>}
      {override && <TextInput mt="sm" label="Reason for the content exception" description="Recorded in the audit and library. Do not include secrets. This cannot bypass a bad signature or changed file bytes."
        maxLength={512} value={overrideReason} onChange={(event) => setOverrideReason(event.currentTarget.value)} disabled={blocked} />}
    </Alert>
    <Paper withBorder p="md" radius="md">
      <Stack gap="sm">
        <Text fw={700}>Upload from this computer</Text>
        {!permission.can('import') && <Text size="sm" c="dimmed">Your account does not have permission to import content.</Text>}
        <Text size="sm" c="dimmed">XML or ZIP, up to 32 MiB per file. Files are validated and indexed one at a time. Uploads work offline; publisher authenticity is not verified.</Text>
        {plainUploadNeedsException() && <Text size="sm">Plain uploads require the explicit human exception above. For an operator-attested bundle, use folder import.</Text>}
        <FileInput label="Choose content files" placeholder="Select XML or ZIP files" multiple clearable accept=".xml,.zip" value={files} onChange={setFiles} disabled={blocked} />
        <Button loading={busy === 'upload'} disabled={importBlocked || !files.length || (plainUploadNeedsException() && !override)} onClick={() => void act('upload', upload)} style={{ alignSelf: 'flex-start' }}>Upload {files.length || ''} file{files.length === 1 ? '' : 's'}</Button>
        {uploads.length > 0 && <LibraryTable rows={uploads} label="upload results" empty="No uploads." searchText={(u) => `${u.file.name} ${u.state}`}
          headings={<><Table.Th>File</Table.Th><Table.Th>Result</Table.Th></>}
          render={(u, i) => <Table.Tr key={i}><Table.Td><Text size="sm" style={{ overflowWrap: 'anywhere' }}>{u.file.name}</Text></Table.Td><Table.Td>
            <Badge color={u.state === 'done' ? 'teal' : u.state === 'failed' ? 'red' : 'blue'} variant="light">{u.state === 'done' ? 'Accepted' : u.state}</Badge>
            {u.error && <Text size="xs" c="red">{u.error}</Text>}
            {u.result && <Stack gap={4} mt={4}>
              <Text size="xs" style={{ overflowWrap: 'anywhere' }}>{u.result.record.benchmark_id ?? u.result.record.product_key ?? 'Unmapped product'} · {u.result.record.version_label ?? u.result.record.benchmark_release ?? 'Version not provided'}</Text>
              {u.result.record.version_label && u.result.record.benchmark_release && <Text size="xs" c="dimmed">{u.result.record.benchmark_release}</Text>}
              <FileProvenance file={u.result.record} />
            </Stack>}
            {u.result?.delta && <DeltaRow d={u.result.delta} />}
          </Table.Td></Table.Tr>} />}
      </Stack>
    </Paper>

    <Paper withBorder p="md" radius="md">
      <Stack gap="sm">
        <Text fw={700}>Transfer with a manifest</Text>
        {!permission.can('export') && <Text size="sm" c="dimmed">Exporting a manifest requires the export permission and a node grant.</Text>}
        <Text size="sm" c="dimmed">Export a manifest for your saved selections. Retrieve its files on a connected machine, then import the folder available to this server.</Text>
        <Group align="flex-end">
          <Button variant="light" loading={busy === 'manifest'} disabled={selectionBlocked || !permission.can('export') || !library.selection.wanted.length} onClick={() => void act('manifest', async () => {
            const manifest = await api.writeManifest();
            requireAction('export');
            downloadJson('manifest.json', manifestText(manifest));
            notifications.show({ message: `Manifest exported: ${manifest.items.length} items` });
          })}>Download manifest</Button>
          <TextInput label="Import folder on the server" placeholder="E:\stig-content" value={folder} disabled={blocked} style={{ flex: 1, minWidth: 220 }} onChange={(e) => setFolder(e.currentTarget.value)} />
          <Button variant="light" loading={busy === 'import'} disabled={importBlocked || !folder.trim()} onClick={() => void act('import', async () => {
            const result = await api.importDir(folder.trim(), importException());
            requireAction('import');
            setImported(result); await onRefresh();
          })}>Import folder</Button>
        </Group>
        {imported && <Stack gap="sm">
          <Text size="sm">Imported {imported.imported.length} file(s). Integrity checks: {imported.verified_by}.</Text>
          <Text size="xs" c={contentProvenance(imported.authenticity).color}>{contentProvenance(imported.authenticity).text}</Text>
          {importNotices.length > 0 && <LibraryTable rows={importNotices} label="import notices" searchText={(r) => `${r.filename} ${r.reason}`} empty="No notices."
            headings={<><Table.Th>File</Table.Th><Table.Th>State</Table.Th><Table.Th>Reason</Table.Th></>}
            render={(r, i) => <Table.Tr key={i}><Table.Td>{r.filename}</Table.Td><Table.Td>{r.state}</Table.Td><Table.Td>{r.reason}</Table.Td></Table.Tr>} />}
          {imported.deltas.map((d) => <DeltaRow key={d.id} d={d} />)}
        </Stack>}
      </Stack>
    </Paper>

    <Stack gap="sm">
      <Group justify="space-between"><Text fw={700}>Transfer history</Text><Text size="xs" c="dimmed">Latest 20 jobs · active jobs refresh automatically</Text></Group>
      {!jobs.length ? <Text size="sm" c="dimmed">No download jobs recorded.</Text> : <Accordion multiple variant="contained" value={openJobs} onChange={setOpenJobs}>
        {jobs.map((job) => <Accordion.Item key={job.id} value={job.id}>
          <Accordion.Control><Group gap="sm"><Badge variant="light" color={STATE_COLOR[job.state]}>{job.state}</Badge><Text size="sm">{job.files.filter((f) => f.state === 'done').length} / {job.files.length} files · {fmtZonedTime(job.created_at)}</Text><Text size="xs" c="dimmed">{job.id}</Text></Group></Accordion.Control>
          <Accordion.Panel><JobProgress job={job} /></Accordion.Panel>
        </Accordion.Item>)}
      </Accordion>}
    </Stack>
    </>}
  </Stack>;
}
