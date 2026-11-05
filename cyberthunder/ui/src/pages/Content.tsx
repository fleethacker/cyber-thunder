import { Accordion, Alert, Badge, Button, Group, Paper, SimpleGrid, Stack, Table, Tabs, Text } from '@mantine/core';
import { IconBooks, IconCloudDownload, IconRefresh, IconSettings } from '@tabler/icons-react';
import { useCallback, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api, errorText } from '../api/client';
import { actorProblem } from '../components/ActorChip';
import { ContentUpdates, jobRunning } from '../components/ContentUpdates';
import { LibrarySelections } from '../components/LibrarySelections';
import { CatalogTable, HeldTable, LibraryTable } from '../components/LibraryTables';
import { ErrorBox, Loading, PageTitle } from '../components/common';
import { fmtZonedTime } from '../lib/format';
import { useAsync, useInterval } from '../lib/hooks';
import { useAppState } from '../state/AppState';

export default function Content() {
  const state = useAsync(api.stigLibrary, []);
  const { status, actor } = useAppState();
  const [params, setParams] = useSearchParams();
  const [dirty, setDirty] = useState(false);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [refreshError, setRefreshError] = useState<string | null>(null);
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
  const library = state.data;
  const running = library?.jobs.some(jobRunning) ?? false;
  useInterval(() => { if (!state.loading && !checking && !refreshRequest.current) void refresh().catch(() => {}); }, running ? 1500 : 10000, !!library);
  const connected = status?.link.connected ?? library?.connected ?? false;
  const blocked = !status || status.kill.engaged || !!actorProblem(actor) || !!refreshError;
  const selectedTab = params.get('tab');
  const tab = selectedTab === 'selections' || selectedTab === 'transfers' ? selectedTab : 'library';
  const check = async () => {
    setChecking(true);
    setError(null);
    try { await api.checkUpdates('live'); }
    catch (e) { setError(errorText(e)); }
    finally { await refresh().catch(() => {}); setChecking(false); }
  };
  return <Stack gap="md">
    <PageTitle title="STIG Library" subtitle="Local releases, saved update selections, and content transfers."
      right={<><Button variant="default" leftSection={<IconRefresh size={16} />} loading={state.loading} disabled={checking} onClick={() => void (library ? refresh().catch(() => {}) : state.reload())}>Refresh local view</Button>
        <Button leftSection={<IconCloudDownload size={16} />} loading={checking} disabled={!library || !connected || dirty || blocked || running} onClick={() => void check()}>Check live index</Button></>} />
    {!library ? state.error ? <ErrorBox error={state.error} onRetry={() => void state.reload()} /> : <Loading what="Reading STIG Library" /> : <>
      {state.error && <ErrorBox error={`Could not refresh the library. Displaying the last loaded view. ${state.error}`} onRetry={() => void state.reload()} />}
      {refreshError && <ErrorBox error={`Could not refresh the library. Displaying the last loaded view. ${refreshError}`} onRetry={() => void refresh().catch(() => {})} />}
      {error && <ErrorBox error={error} />}
      {blocked && !refreshError && <Alert color="yellow">{status?.kill.engaged ? 'Kill switch engaged. Downloads, imports and changes are blocked.' : actorProblem(actor) ? 'Set your acting name in the header to save selections, check updates, or import content.' : 'Waiting for node status before enabling changes.'}</Alert>}
      <Paper withBorder p="md" radius="md">
        <Stack gap="sm">
          <Group justify="space-between">
            <Group gap="xs"><Badge variant="light" color={library.catalog.source === 'live' ? 'blue' : 'orange'}>{library.catalog.source === 'live' ? 'Last live index' : 'Snapshot index'}</Badge><Text size="sm">{library.catalog.total_entries.toLocaleString()} index entries · {library.products.length.toLocaleString()} products</Text></Group>
            <Badge variant="light" color={connected ? 'teal' : 'orange'}>{connected ? 'Connected' : 'Offline'}</Badge>
          </Group>
          <Text size="xs" c="dimmed">Index saved: {fmtZonedTime(library.catalog.saved_at)}. Publisher dates are shown as supplied; local event times include the timezone offset.</Text>
          <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="sm">
            {[
              ['Last successful live check', library.sync.last_successful_check_at, 'Never checked live'],
              ['Last download', library.sync.last_download_at, 'No download recorded'],
              ['Last local import', library.sync.last_import_at, 'No import recorded'],
            ].map(([label, time, empty]) => <Paper key={label} withBorder p="sm" radius="md"><Text size="xs" c="dimmed" fw={600}>{label}</Text><Text size="sm" fw={600} mt={4}>{fmtZonedTime(time, empty ?? undefined)}</Text></Paper>)}
          </SimpleGrid>
          {(library.catalog.source === 'snapshot' || !library.sync.last_successful_check_at) && <Text size="sm" c="orange">Live freshness is unconfirmed. The local index can guide selections and offline transfers.</Text>}
          {library.sync.last_attempt_at && <Text size="xs" c="dimmed">Last check attempt: {fmtZonedTime(library.sync.last_attempt_at)} · {library.sync.last_attempt_status ?? 'Status unavailable'}</Text>}
          {library.sync.last_error && <Alert color="orange" title="Last check did not complete">{library.sync.last_error}</Alert>}
          {dirty && <Text size="sm" c="orange">Unsaved selections. Save or discard them before checking for updates.</Text>}
        </Stack>
      </Paper>
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
      <Tabs value={tab} onChange={(value) => setParams(value === 'library' ? {} : { tab: value ?? 'library' }, { replace: true })}>
        <Tabs.List>
          <Tabs.Tab value="library" leftSection={<IconBooks size={16} />}>Library</Tabs.Tab>
          <Tabs.Tab value="selections" leftSection={<IconSettings size={16} />}>Update selections{dirty ? ' •' : ''}</Tabs.Tab>
          <Tabs.Tab value="transfers" leftSection={<IconCloudDownload size={16} />}>Transfers / import{running ? ' •' : ''}</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="library" pt="lg">
          <Stack gap="lg">
            <Group justify="space-between"><Text fw={700}>Local files ({library.held.files.length})</Text><Text size="xs" c="dimmed">{library.held.scap.length} indexed SCAP datastream(s)</Text></Group>
            <HeldTable files={library.held.files} />
            <Text fw={700}>Rule catalogs ({library.catalogs.length})</Text>
            <Text size="sm" c="dimmed">Includes previous imports and bundled reference XMLs. Bundled references do not represent content synchronized from cyber.mil.</Text>
            <CatalogTable catalogs={library.catalogs} />
          </Stack>
        </Tabs.Panel>
        <Tabs.Panel value="selections" pt="lg"><LibrarySelections library={library} disabled={blocked || checking} onSaved={refresh} onDirtyChange={setDirty} /></Tabs.Panel>
        <Tabs.Panel value="transfers" pt="lg"><ContentUpdates library={library} dirty={dirty} disabled={blocked || checking} onRefresh={refresh} /></Tabs.Panel>
      </Tabs>
    </>}
  </Stack>;
}
