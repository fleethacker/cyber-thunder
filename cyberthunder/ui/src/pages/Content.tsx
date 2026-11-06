import { Accordion, Alert, Badge, Button, Group, Paper, SimpleGrid, Stack, Table, Tabs, Text } from '@mantine/core';
import { IconBooks, IconCloudDownload, IconRefresh, IconSettings } from '@tabler/icons-react';
import { useCallback, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { linkLabel } from '../lib/linkPresentation';
import { api, errorText } from '../api/client';
import type { UpdateCheck } from '../api/types';
import { actorProblem } from '../components/ActorChip';
import { ContentUpdates, jobRunning } from '../components/ContentUpdates';
import { LibrarySelections } from '../components/LibrarySelections';
import { CatalogTable, HeldTable, LibraryTable, type CatalogLibrary } from '../components/LibraryTables';
import { ErrorBox, Loading, PageTitle } from '../components/common';
import { fmtZonedTime } from '../lib/format';
import { useAsync, useInterval } from '../lib/hooks';
import { useAppState } from '../state/AppState';
import { contentTask, isMaintained, type ContentTask } from '../lib/contentTasks';

export default function Content() {
  const state = useAsync(api.stigLibrary, []);
  const { status, statusError, actor } = useAppState();
  const [params, setParams] = useSearchParams();
  const [dirty, setDirty] = useState(false);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [refreshError, setRefreshError] = useState<string | null>(null);
  const [snapshotReport, setSnapshotReport] = useState<UpdateCheck | null>(null);
  const refreshRequest = useRef<Promise<void> | null>(null);
  const refresh = useCallback(() => {
    const previous = refreshRequest.current ?? Promise.resolve();
    const pending = previous.catch(() => {}).then(() => api.stigLibrary()).then((data) => {
      state.setData(data);
      setRefreshError(null);
    }).catch((e) => { setRefreshError(errorText(e)); throw e; })
      .finally(() => { if (refreshRequest.current === pending) refreshRequest.current = null; });
    refreshRequest.current = pending;
    return pending;
  }, [state.setData]);
  const library: CatalogLibrary | undefined = state.data;
  const running = library?.jobs.some(jobRunning) ?? false;
  useInterval(() => { if (!state.loading && !checking && !refreshRequest.current) void refresh().catch(() => {}); }, running ? 1500 : 10000, !!library);
  const link = status?.global_details === false ? null : status?.link;
  const connected = link === null ? null : link?.connected ?? library?.connected ?? false;
  const blocked = !status || !!statusError || status.kill.engaged || !!actorProblem(actor) || !!refreshError;
  const productKey = params.get('product');
  const tab = contentTask(params.get('tab'), productKey);
  const selectTask = (value: ContentTask) => {
    const next = new URLSearchParams(params); next.set('tab', value); setParams(next, { replace: true });
  };
  const selectProduct = (key: string | null) => {
    const next = new URLSearchParams(params);
    if (key) { next.set('product', key); next.set('tab', 'browse'); } else next.delete('product');
    setParams(next, { replace: true });
  };
  const check = async (source: 'live' | 'snapshot' = 'live') => {
    if (!library || (source === 'live' && !connected) || dirty || blocked || running || checking) return;
    setChecking(true);
    setError(null);
    try {
      const report = await api.checkUpdates(source);
      setSnapshotReport(source === 'snapshot' ? report : null);
    }
    catch (e) { setError(errorText(e)); }
    finally { await refresh().catch(() => {}); setChecking(false); }
  };
  return <Stack gap="md">
    <PageTitle title="STIG Library" subtitle="See local content, choose products to maintain, and download or import releases."
      right={<><Button variant="default" leftSection={<IconRefresh size={16} />} loading={state.loading} disabled={checking} onClick={() => void (library ? refresh().catch(() => {}) : state.reload())}>Refresh local view</Button>
        <Button leftSection={<IconCloudDownload size={16} />} loading={checking} disabled={!library || !connected || dirty || blocked || running} onClick={() => void check()}>Check cyber.mil for updates</Button></>} />
    {!library ? state.error ? <ErrorBox error={state.error} onRetry={() => void state.reload()} /> : <Loading what="Reading STIG Library" /> : <>
      {state.error && <ErrorBox error={`Could not refresh the library. Displaying the last loaded view. ${state.error}`} onRetry={() => void state.reload()} />}
      {refreshError && <ErrorBox error={`Could not refresh the library. Displaying the last loaded view. ${refreshError}`} onRetry={() => void refresh().catch(() => {})} />}
      {error && <ErrorBox error={error} />}
      {blocked && !refreshError && <Alert color="yellow">{status?.kill.engaged ? 'Kill switch engaged. Downloads, imports and changes are blocked.' : actorProblem(actor) ? 'Set your acting name in the header to save selections, check updates, or import content.' : 'Waiting for node status before enabling changes.'}</Alert>}
      <Paper withBorder p="md" radius="md">
        <Stack gap="sm">
          <Group justify="space-between">
            <Group gap="xs"><Badge variant="light" color={library.catalog.source === 'live' ? 'blue' : 'orange'}>{library.catalog.source === 'live' ? 'Last live index' : 'Snapshot index'}</Badge><Text size="sm">{library.catalog.total_entries.toLocaleString()} index entries · {library.products.length.toLocaleString()} products</Text></Group>
            <Badge variant="light" color={connected === null ? 'gray' : connected ? 'teal' : 'orange'}>{status?.global_details === false ? 'Link restricted' : linkLabel(link)}</Badge>
          </Group>
          <Text size="xs" c="dimmed">Index saved: {fmtZonedTime(library.catalog.saved_at)}. Publisher dates are shown as supplied; local event times include the timezone offset.</Text>
          <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="sm">
            {[
              ['Last successful cyber.mil check', library.sync.last_successful_check_at, 'No successful check recorded'],
              ['Last download', library.sync.last_download_at, 'No download recorded'],
              ['Last local import', library.sync.last_import_at, 'No import recorded'],
            ].map(([label, time, empty]) => <Paper key={label} withBorder p="sm" radius="md"><Text size="xs" c="dimmed" fw={600}>{label}</Text><Text size="sm" fw={600} mt={4}>{fmtZonedTime(time, empty ?? undefined)}</Text></Paper>)}
          </SimpleGrid>
          {(library.catalog.source === 'snapshot' || library.catalog.live_status === 'unavailable' || !library.sync.last_successful_check_at) && <Text size="sm" c="orange">Live freshness is unconfirmed. The local index can guide selections and offline transfers.</Text>}
          {library.catalog.live_status === 'unavailable' && <Alert color="orange" title="Live index unavailable">
            <Text size="sm">{library.catalog.live_error} The saved catalog remains available. A snapshot check uses the supplied snapshot and does not confirm live freshness or replace the last live catalog.</Text>
          </Alert>}
          <Button variant="default" loading={checking} disabled={dirty || blocked || running} onClick={() => void check('snapshot')}>Check supplied snapshot</Button>
          {snapshotReport && <Alert color="blue" title="Snapshot comparison complete">
            {snapshotReport.index_entries?.toLocaleString()} snapshot publications compared; {snapshotReport.updates.length} update candidates for saved selections. The library continues to show its saved catalog. No live freshness was confirmed and no files were downloaded.
          </Alert>}
          {library.sync.last_attempt_at && <Text size="xs" c="dimmed">Last check attempt: {fmtZonedTime(library.sync.last_attempt_at)} · {library.sync.last_attempt_status ?? 'Status unavailable'}</Text>}
          {library.sync.last_error && <Alert color="orange" title="Last check did not complete">{library.sync.last_error}</Alert>}
          {dirty && <Text size="sm" c="orange">Unsaved selections. Save or discard them before checking for updates.</Text>}
          <Text size="sm">Checking updates refreshes the release list. Downloads require an explicit action or your saved automatic-download setting.</Text>
        </Stack>
      </Paper>
      <Alert color="blue" title="Local content and scan coverage are different">
        Manual STIGs and SRGs provide rules and guidance. SCAP benchmarks contain automated checks, but need a compatible, configured scanner and deployment for the target.
        Downloaded content and bundled rule catalogs do not confirm scan coverage.
      </Alert>
      {library.held.quarantine.length > 0 && <Alert color="red" title={`${library.held.quarantine.length} quarantined file(s)`}>
        <Text size="sm">Quarantined files are excluded from the local library.</Text>
        <Accordion variant="contained" mt="sm"><Accordion.Item value="quarantine"><Accordion.Control>Review quarantine</Accordion.Control><Accordion.Panel>
          <LibraryTable rows={library.held.quarantine} label="quarantined files" searchText={(q) => `${q.filename} ${q.reason}`} empty="No quarantined files."
            headings={<><Table.Th>File</Table.Th><Table.Th>Reason</Table.Th><Table.Th>Quarantined at</Table.Th></>}
            render={(q) => <Table.Tr key={q.filename + q.quarantined_at}><Table.Td>{q.filename}</Table.Td><Table.Td>{q.reason}</Table.Td><Table.Td>{fmtZonedTime(q.quarantined_at)}</Table.Td></Table.Tr>} />
        </Accordion.Panel></Accordion.Item></Accordion>
      </Alert>}
      {!!library.catalog_errors?.length && <Alert color="orange" title="Some rule catalogs could not be read">
        <Text size="sm">The catalog list is incomplete. Review these files before relying on catalog coverage.</Text>
        <Accordion variant="contained" mt="sm"><Accordion.Item value="catalog-errors"><Accordion.Control>Review catalog errors ({library.catalog_errors.length})</Accordion.Control><Accordion.Panel>
          <LibraryTable rows={library.catalog_errors} label="catalog errors" searchText={(item) => `${item.filename} ${item.reason}`} empty="No catalog errors."
            headings={<><Table.Th>File</Table.Th><Table.Th>Reason</Table.Th></>}
            render={(item, index) => <Table.Tr key={`${item.filename}-${index}`}><Table.Td>{item.filename}</Table.Td><Table.Td>{item.reason}</Table.Td></Table.Tr>} />
        </Accordion.Panel></Accordion.Item></Accordion>
      </Alert>}
      <Tabs value={tab} keepMounted onChange={(value) => selectTask(contentTask(value))}>
        <Tabs.List>
          <Tabs.Tab value="downloaded" leftSection={<IconBooks size={16} />}>Downloaded ({library.held.files.length})</Tabs.Tab>
          <Tabs.Tab value="maintained" leftSection={<IconSettings size={16} />}>Maintained ({library.products.filter((p) => isMaintained(p, library.preferences)).length}){dirty ? ' •' : ''}</Tabs.Tab>
          <Tabs.Tab value="updates">Updates ({library.selection.updates.length})</Tabs.Tab>
          <Tabs.Tab value="browse">Browse all ({library.publications?.length ?? library.products.length})</Tabs.Tab>
          <Tabs.Tab value="transfers" leftSection={<IconCloudDownload size={16} />}>Import / transfer{running ? ' •' : ''}</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="downloaded" pt="lg">
          <Stack gap="lg">
            <Group justify="space-between"><Text fw={700}>Downloaded and imported files ({library.held.files.length})</Text><Text size="xs" c="dimmed">{library.held.scap.length} indexed SCAP datastream(s), scanner setup not verified</Text></Group>
            <Text size="sm">These files are local, whether or not their products are selected for maintenance. Manual STIG, SRG and SCAP content are listed separately by type.</Text>
            <Text size="sm" c="dimmed">Active in library identifies the accepted local release. Stored references remain available as history; neither label confirms which release a configured scanner uses.</Text>
            <Group><Button variant="light" onClick={() => selectTask('browse')}>Find another product</Button><Button variant="light" onClick={() => selectTask('transfers')}>Import local content</Button></Group>
            <HeldTable files={library.held.files} onProductSelect={selectProduct} />
            <Text fw={700}>Imported and bundled rule catalogs ({library.catalogs.length})</Text>
            <Text size="sm" c="dimmed">Parsed reference rules are listed separately from downloaded files. Bundled references came with this build; they are not evidence of a cyber.mil download or configured scanner.</Text>
            <CatalogTable catalogs={library.catalogs} />
          </Stack>
        </Tabs.Panel>
        <Tabs.Panel value={tab === 'browse' ? 'browse' : 'maintained'} pt="lg">
          <LibrarySelections library={library} disabled={blocked || checking} onSaved={refresh} onDirtyChange={setDirty}
            view={tab === 'browse' ? 'browse' : 'maintained'} productKey={productKey} onProductChange={selectProduct} onBrowse={() => selectTask('browse')} />
        </Tabs.Panel>
        <Tabs.Panel value={tab === 'updates' ? 'updates' : 'transfers'} pt="lg">
          <ContentUpdates library={library} dirty={dirty} disabled={blocked || checking} onRefresh={refresh}
            view={tab === 'updates' ? 'updates' : 'transfers'} onProductSelect={selectProduct} onMaintained={() => selectTask('maintained')} onTransfers={() => selectTask('transfers')} />
        </Tabs.Panel>
      </Tabs>
    </>}
  </Stack>;
}
