import { Alert, Button, Checkbox, FileInput, Group, Paper, Stack, Text } from '@mantine/core';
import { IconCloudDownload, IconDownload, IconRefresh, IconUpload } from '@tabler/icons-react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { api, ApiError, errorText } from '../api/client';
import type { VulnerabilityJob, VulnerabilitySettingsInput, VulnerabilityStatus as Status } from '../api/types';
import { actorProblem } from '../components/ActorChip';
import { ErrorBox, Loading, PageTitle } from '../components/common';
import { VulnerabilitySchedule } from '../components/VulnerabilitySchedule';
import { VulnerabilityJobs, vulnerabilityJobActive, VulnerabilityStatus } from '../components/VulnerabilityStatus';
import { useInterval } from '../lib/hooks';
import { useAppState } from '../state/AppState';

type Operation = 'update' | 'import' | 'export' | 'settings';

export default function Vulnerabilities() {
  const { status, statusError, actor } = useAppState();
  const [data, setData] = useState<Status | null>(null);
  const [jobs, setJobs] = useState<VulnerabilityJob[]>([]);
  const [readError, setReadError] = useState<string | null>(null);
  const [jobsError, setJobsError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(true);
  const [busy, setBusy] = useState<Operation | null>(null);
  const [includeJava, setIncludeJava] = useState(true);
  const [file, setFile] = useState<File | null>(null);
  const alive = useRef(true);
  const refreshRequest = useRef<Promise<Status> | null>(null);
  const operation = useRef<Operation | null>(null);

  const refresh = useCallback((): Promise<Status> => {
    if (refreshRequest.current) return refreshRequest.current;
    setRefreshing(true);
    const pending = Promise.allSettled([api.vulnerabilities(), api.vulnerabilityJobs()]).then(([local, history]) => {
      if (alive.current) {
        if (local.status === 'fulfilled') { setData(local.value); setReadError(null); }
        else setReadError(errorText(local.reason));
        if (history.status === 'fulfilled') { setJobs(history.value.jobs); setJobsError(null); }
        else setJobsError(errorText(history.reason));
      }
      if (local.status === 'rejected') throw local.reason;
      return local.value;
    }).finally(() => {
      if (refreshRequest.current === pending) refreshRequest.current = null;
      if (alive.current) setRefreshing(false);
    });
    refreshRequest.current = pending;
    return pending;
  }, []);

  useEffect(() => {
    alive.current = true;
    void refresh().catch(() => {});
    return () => { alive.current = false; };
  }, [refresh]);

  const shownJobs = data?.active_job && !jobs.some((job) => job.id === data.active_job?.id) ? [data.active_job, ...jobs] : jobs;
  const running = shownJobs.some(vulnerabilityJobActive);
  useInterval(() => { if (!operation.current && !refreshRequest.current) void refresh().catch(() => {}); }, running ? 1500 : 10000, !!data || running);

  const gateReason = status?.kill.engaged ? 'Kill switch engaged. Database updates, imports, exports and schedule changes are blocked.'
    : !status || statusError ? 'Waiting for current node status before enabling database actions.'
    : actorProblem(actor) ? 'Set a valid acting name in the header to update, import, export, or save a schedule.'
    : readError || jobsError ? 'Refresh the local status and update history before making changes.' : null;
  const disabled = !!gateReason || !data || !!busy || refreshing;
  const online = status?.global_details === false || status?.link === null ? null : !!status?.link?.connected;
  const canUpdate = online && !!data?.engine.available && !!data.engine.supported;
  const canExport = !!data?.generation && data.databases.some((db) => db.kind === 'main' && db.present);
  const fileError = file && (!/\.zip$/i.test(file.name) || file.size === 0) ? 'Choose a nonempty ZIP file.' : null;

  const run = async <T,>(kind: Operation, action: () => Promise<T>): Promise<T> => {
    if (disabled || operation.current || refreshRequest.current || ((kind === 'update' || kind === 'import') && running)) {
      throw new ApiError(409, gateReason ?? 'Wait for the current database operation to finish.');
    }
    operation.current = kind;
    setBusy(kind);
    setActionError(null);
    setMessage(null);
    try { return await action(); }
    catch (e) { if (kind !== 'settings') setActionError(errorText(e)); throw e; }
    finally {
      if (kind !== 'settings') await refresh().catch(() => {});
      operation.current = null;
      if (alive.current) setBusy(null);
    }
  };

  const update = async () => {
    if (!canUpdate) return;
    await run('update', async () => {
      const job = await api.updateVulnerabilityDatabases(includeJava);
      setJobs((previous) => [job, ...previous.filter((item) => item.id !== job.id)]);
      setData((previous) => previous ? { ...previous, active_job: job } : previous);
      setMessage('Database update requested. Progress and any errors appear below.');
    }).catch(() => {});
  };
  const upload = async () => {
    if (!file || fileError) return;
    await run('import', async () => {
      setData(await api.importVulnerabilityBundle(file));
      setFile(null);
      setMessage('Offline databases imported. Review their source and freshness below.');
    }).catch(() => {});
  };
  const download = async () => {
    if (!canExport) return;
    await run('export', async () => {
      const blob = await api.exportVulnerabilityBundle();
      const href = URL.createObjectURL(blob);
      const link = document.createElement('a');
      try {
        link.href = href;
        link.download = 'cyber-thunder-vulnerability-databases.zip';
        document.body.appendChild(link);
        link.click();
        setMessage('Database ZIP prepared and sent to your browser for download.');
      } finally {
        link.remove();
        window.setTimeout(() => URL.revokeObjectURL(href), 1000);
      }
    }).catch(() => {});
  };
  const saveSettings = (input: VulnerabilitySettingsInput) => run('settings', async () => {
    const saved = await api.saveVulnerabilitySettings(input);
    setData((previous) => previous ? { ...previous, settings: saved } : previous);
    return saved;
  });

  return <Stack gap="md">
    <PageTitle title="Vulnerability Data" subtitle="Manage the local databases used to find known vulnerabilities."
      right={<Button variant="default" leftSection={<IconRefresh size={16} />} loading={refreshing} disabled={!!busy} onClick={() => void refresh().catch(() => {})}>Refresh local status</Button>} />
    <Alert color="blue" title="What these databases provide">
      <Stack gap="xs">
        <Text size="sm">Opening this page or refreshing its status does not download databases. Use Update databases, upload an offline ZIP, or explicitly enable a saved schedule.</Text>
        <Text size="sm">Offline databases let the scanner consult known vulnerability data without downloading it. Container images must still be available locally or from a reachable registry. The database ZIP does not include images.</Text>
        <Text size="sm">Fresh databases do not guarantee full vulnerability coverage. Missing images, unsupported packages, stale data and scanner errors can leave gaps. Database changes are recorded in the audit log and do not authorize changes to scanned targets.</Text>
      </Stack>
    </Alert>
    {readError && <ErrorBox error={`Could not read database status.${data ? ' Showing the last loaded status; it may be out of date.' : ''} ${readError}`} onRetry={() => void refresh().catch(() => {})} />}
    {jobsError && <ErrorBox error={`Could not read update progress. Progress may be out of date. ${jobsError}`} onRetry={() => void refresh().catch(() => {})} />}
    {actionError && <ErrorBox error={actionError} />}
    {message && <Alert color="blue" role="status">{message}</Alert>}
    {gateReason && <Alert color="yellow">{gateReason}</Alert>}
    {!data ? !readError && <Loading what="Reading local database status" /> : <>
      <Paper withBorder p="md" radius="md"><Stack gap="sm">
        <Text component="h2" size="lg" fw={700} m={0}>Update databases</Text>
        <Text size="sm">Download the main database from the official repositories. The existing databases stay available until the new set passes checks.</Text>
        <Checkbox label="Include Java database in this update" checked={includeJava} disabled={disabled || running} onChange={(e) => setIncludeJava(e.currentTarget.checked)} />
        {!online && <Text size="sm" c={online === null ? 'dimmed' : 'orange'}>{online === null
          ? 'Link status is restricted or unknown. Online update availability cannot be determined.'
          : 'The node is offline. Online updates are unavailable; you can upload an offline ZIP.'}</Text>}
        {running && <Text size="sm" role="status">An update is active. Wait for it to finish before starting another update or import.</Text>}
        <Group><Button leftSection={<IconCloudDownload size={16} />} loading={busy === 'update'} disabled={disabled || running || !canUpdate} onClick={() => void update()}>Update databases</Button></Group>
      </Stack></Paper>
      <VulnerabilityStatus data={data} />
      <Paper withBorder p="md" radius="md"><Stack gap="sm">
        <Text component="h2" size="lg" fw={700} m={0}>Offline transfer</Text>
        <Text size="sm">Export the installed databases to move them to another node. Upload a database ZIP exported by Cyber Thunder to install it here. An import checks file integrity, not publisher authenticity; use a source you trust independently.</Text>
        <FileInput label="Offline database ZIP" placeholder="Choose a ZIP file" accept=".zip,application/zip,application/x-zip-compressed" clearable value={file} onChange={setFile} disabled={disabled || running} error={fileError} />
        <Group>
          <Button leftSection={<IconUpload size={16} />} loading={busy === 'import'} disabled={disabled || running || !file || !!fileError} onClick={() => void upload()}>Upload offline ZIP</Button>
          <Button variant="default" leftSection={<IconDownload size={16} />} loading={busy === 'export'} disabled={disabled || !canExport} onClick={() => void download()}>Export ZIP</Button>
        </Group>
        {!canExport && <Text size="sm" c="dimmed">Install a main database before exporting.</Text>}
      </Stack></Paper>
      <VulnerabilitySchedule settings={data.settings} disabled={disabled} onSave={saveSettings} onReload={async () => (await refresh()).settings} />
    </>}
    {(data || shownJobs.length > 0) && <VulnerabilityJobs jobs={shownJobs} />}
  </Stack>;
}
