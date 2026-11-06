import { Alert, Badge, Button, Drawer, Group, ScrollArea, Stack, Table, Text } from '@mantine/core';
import { useEffect, useRef, useState } from 'react';
import { api, errorText } from '../api/client';
import { authorityRevision } from '../api/identity';
import type { DiscoveredAsset, Target, VsphereRun, VsphereRunSummary } from '../api/types';
import { PermissionButton, usePermissions } from './PermissionGate';

export function isVsphereTarget(target: Target): boolean {
  return target.transport === 'vsphere' || target.options?.hypervisor === 'vsphere';
}

function targetKey(target: Target | null): string {
  if (!target) return '';
  const { last_scan: _scan, notes: _notes, added_at: _added, ...configuration } = target;
  return JSON.stringify(configuration);
}

function belongs(run: VsphereRunSummary, target: Target): boolean {
  return run.source === 'vsphere' && run.target_id === target.id && run.authorization_scope?.target_id === target.id
    && run.authorization_scope.environment === (target.environment ?? 'default')
    && (!target.authorization_id || run.authorization_scope.authorization_id === target.authorization_id);
}

function summary(run: VsphereRun): VsphereRunSummary {
  const { observations: _observations, ...rest } = run;
  return rest;
}

function statusText(run: VsphereRunSummary): string {
  if (run.status === 'finished' && run.complete) return 'Complete';
  if (run.status === 'failed') return 'Failed — incomplete';
  if (run.status === 'stopped') return 'Stopped — incomplete';
  if (run.status === 'running') return 'Running — incomplete';
  return 'Incomplete';
}

const value = (input: unknown) => typeof input === 'string' && input ? input : 'Not reported';
function date(input: string): string {
  const parsed = new Date(input);
  return Number.isNaN(parsed.valueOf()) ? 'Unknown date' : parsed.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC');
}
function reportedIPs(asset: DiscoveredAsset): string {
  const ips = asset.facts.reported_addresses;
  return Array.isArray(ips) && ips.some(ip => typeof ip === 'string' && ip)
    ? ips.filter(ip => typeof ip === 'string' && ip).join(', ') : 'Not reported';
}

/** Pure presentation is also rendered in fixtures with real table and alert widgets. */
export function VsphereSnapshot({ run }: { run: VsphereRun }) {
  const complete = run.status === 'finished' && run.complete;
  return <Stack gap="sm">
    <Group><Text fw={600}>Selected collection</Text><Badge color={complete ? 'teal' : 'orange'}>{statusText(run)}</Badge></Group>
    <Text size="sm">Started {date(run.started_at)} · Finished {run.finished_at ? date(run.finished_at) : 'Not finished'}</Text>
    {!complete ? <Alert color="orange" title="Inventory snapshot incomplete">
      {run.error ? `Collection result: ${run.error}. ` : ''}
      {run.collection_started ? 'Collection was invoked; successful connectivity is not established by this status. '
        : 'The collector was not invoked. '}
      No complete inventory is available from this run. This is not evidence of an empty inventory.
    </Alert> : run.observations.length === 0 ? <Alert color="blue" title="Complete empty inventory">
      This completed collection returned no observations visible to the configured source account within the saved ranges.
    </Alert> : <ScrollArea>
      <Table striped withTableBorder miw={850} aria-label="vSphere inventory observations">
        <Table.Thead><Table.Tr><Table.Th>Name</Table.Th><Table.Th>Type</Table.Th><Table.Th>Reported IP</Table.Th>
          <Table.Th>Power state</Table.Th><Table.Th>Evidence</Table.Th></Table.Tr></Table.Thead>
        <Table.Tbody>{run.observations.map(asset => <Table.Tr key={asset.id}>
          <Table.Td><Text size="sm" fw={600}>{asset.hostname || value(asset.facts.vsphere_ref)}</Text>
            <Text size="xs" c="dimmed">{value(asset.facts.vsphere_ref)}</Text></Table.Td>
          <Table.Td>{asset.facts.vsphere_kind === 'VirtualMachine' ? 'VM' : asset.facts.vsphere_kind === 'HostSystem' ? 'ESXi host' : 'Unknown'}</Table.Td>
          <Table.Td>{reportedIPs(asset)}</Table.Td>
          <Table.Td>{value(asset.facts.power_state)}</Table.Td>
          <Table.Td><Stack gap={2}>{asset.evidence.map((e, i) => <Text key={i} size="sm">{e}</Text>)}
            {asset.notes && <Text size="sm" c="dimmed">{asset.notes}</Text>}</Stack></Table.Td>
        </Table.Tr>)}</Table.Tbody>
      </Table>
    </ScrollArea>}
  </Stack>;
}

type View = {
  key: string; history: VsphereRunSummary[] | null; historyError: string | null;
  selected: VsphereRun | null; error: string | null; busy: 'history' | 'detail' | 'collect' | null;
};
const empty = (key: string): View => ({ key, history: null, historyError: null, selected: null, error: null, busy: null });
type Ticket = { key: string; revision: number; action: 'read' | 'discover' };

export function VsphereInventory({ target, onClose, blocked = null }: {
  target: Target | null; onClose: () => void; blocked?: string | null;
}) {
  const permission = usePermissions();
  const read = permission.can('read'), discover = permission.can('discover');
  const revision = authorityRevision();
  const key = JSON.stringify([targetKey(target), revision, read, discover]);
  const current = useRef({ key, blocked, target });
  current.current = { key, blocked, target };
  const active = useRef<string | null>(null);
  const pending = useRef<Ticket | null>(null);
  const [state, setState] = useState<View>(() => empty(key));
  // Hide an obsolete view during render, before effect cleanup runs.
  const view = state.key === key && read ? state : empty(key);

  const matches = (ticket: Ticket) => pending.current === ticket && active.current === ticket.key
    && current.current.key === ticket.key && authorityRevision() === ticket.revision;
  const allowed = (ticket: Ticket) => matches(ticket) && permission.can('read')
    && (ticket.action === 'read' || (permission.can('discover') && !current.current.blocked && current.current.target?.in_scope));
  const begin = (action: Ticket['action']): Ticket | null => {
    if (!target || current.current.key !== key || active.current !== key || pending.current
      || revision !== authorityRevision() || !permission.can('read')
      || (action === 'discover' && (!permission.can('discover') || current.current.blocked || !target.in_scope))) return null;
    const ticket = { key, revision, action };
    pending.current = ticket;
    return ticket;
  };
  const finish = (ticket: Ticket) => {
    const same = matches(ticket);
    if (pending.current === ticket) pending.current = null;
    if (same) setState(old => ({ ...old, busy: null }));
  };
  const fail = (ticket: Ticket, error: unknown, history = false) => {
    if (!allowed(ticket)) return;
    const denied = typeof error === 'object' && error !== null && 'status' in error && [401, 403].includes(Number(error.status));
    setState(old => ({ ...old, selected: null, ...(denied ? { history: null } : {}),
      ...(history ? { history: null, historyError: errorText(error) } : { error: errorText(error) }) }));
  };

  const loadHistory = async () => {
    const ticket = begin('read');
    if (!ticket || !target) return;
    setState({ ...empty(key), busy: 'history' });
    try {
      const rows = await api.vsphereRuns(target.id);
      if (!allowed(ticket)) return;
      if (rows.some(run => !belongs(run, target))) throw new Error('Source history no longer matches this target. Refresh inventory before reopening.');
      setState(old => ({ ...old, history: rows.slice(0, 20) }));
    } catch (e) { fail(ticket, e, true); }
    finally { finish(ticket); }
  };

  const select = async (runId: string) => {
    const ticket = begin('read');
    if (!ticket || !target) return;
    setState(old => ({ ...old, selected: null, error: null, busy: 'detail' }));
    try {
      const run = await api.vsphereRun(target.id, runId);
      if (!allowed(ticket)) return;
      if (run.id !== runId || !belongs(run, target)) throw new Error('Collection no longer matches this source. Refresh its history.');
      setState(old => ({ ...old, selected: run }));
    } catch (e) { fail(ticket, e); }
    finally { finish(ticket); }
  };

  const collect = async () => {
    const ticket = begin('discover');
    if (!ticket || !target) return;
    setState(old => ({ ...old, selected: null, error: null, busy: 'collect' }));
    try {
      const run = await api.vsphereCollect(target.id);
      if (!allowed(ticket)) return;
      if (!belongs(run, target)) throw new Error('Collection no longer matches this target. Refresh inventory before reopening.');
      setState(old => ({ ...old, selected: run, history: [summary(run), ...(old.history ?? []).filter(r => r.id !== run.id)].slice(0, 20) }));
    } catch (e) { fail(ticket, e); }
    finally { finish(ticket); }
  };

  useEffect(() => {
    active.current = key;
    pending.current = null;
    setState(empty(key));
    if (target && read) void loadHistory();
    return () => { active.current = null; pending.current = null; };
  }, [key]);

  const close = () => {
    active.current = null; pending.current = null;
    setState(empty(key));
    onClose();
  };

  if (!target) return null;
  return <Drawer opened onClose={close} position="right" size="xl" title={<Text fw={700}>vSphere inventory: {target.name}</Text>}>
    <Stack>
      <Text fw={600}>Your source collections</Text>
      <Text size="sm" c="dimmed">Saved inventory for this source and your account. Reported addresses do not establish guest reachability.
        Collection does not add targets, grant guest access or start scans.</Text>
      {!read ? <Alert color="yellow">{permission.reason('read')}</Alert> : <>
        <Group>
          <PermissionButton action="read" variant="default" disabled={!!view.busy} onClick={() => void loadHistory()}>Refresh source history</PermissionButton>
          <PermissionButton action={['read', 'discover']} loading={view.busy === 'collect'}
            disabled={!!view.busy || !!blocked || !target?.in_scope} onClick={() => void collect()}>Collect inventory</PermissionButton>
        </Group>
        {(blocked || !target?.in_scope) && <Alert color="yellow">{blocked || 'This source is out of scope. Collection is unavailable.'}</Alert>}
        {view.busy && <Text role="status">{view.busy === 'history' ? 'Loading source history…' : view.busy === 'detail' ? 'Loading saved collection…' : 'Collecting source inventory…'}</Text>}
        {view.historyError && <Alert color="red" title="Source history unavailable">{view.historyError}</Alert>}
        {view.error && <Alert color="red" title="Source request failed">{view.error} Refresh source history before retrying a collection; its completion may be unknown.</Alert>}
        {view.history?.length === 0 && !view.historyError && !view.error && !view.busy
          && <Alert color="blue">No saved collections for your account and this source.</Alert>}
        {!!view.history?.length && <>
          <Text size="sm">{view.historyError ? 'Showing the collection returned by this request; saved history is still unavailable.'
            : `Latest ${view.history.length} saved collections (up to 20). Select one to read its observations.`}</Text>
          <ScrollArea><Table aria-label="Your source collections" miw={650}>
            <Table.Thead><Table.Tr><Table.Th>Started</Table.Th><Table.Th>Finished</Table.Th><Table.Th>Status</Table.Th><Table.Th>Observations</Table.Th><Table.Th>Details</Table.Th></Table.Tr></Table.Thead>
            <Table.Tbody>{view.history.map(run => <Table.Tr key={run.id}>
              <Table.Td>{date(run.started_at)}</Table.Td><Table.Td>{run.finished_at ? date(run.finished_at) : 'Not finished'}</Table.Td>
              <Table.Td>{statusText(run)}</Table.Td><Table.Td>{run.complete && run.status === 'finished' ? run.observation_count : 'Incomplete'}</Table.Td>
              <Table.Td><PermissionButton action="read" size="xs" variant="light" disabled={!!view.busy}
                aria-label={`View collection ${run.id}`} aria-pressed={view.selected?.id === run.id}
                onClick={() => void select(run.id)}>View collection</PermissionButton></Table.Td>
            </Table.Tr>)}</Table.Tbody>
          </Table></ScrollArea>
        </>}
        {view.selected && <VsphereSnapshot run={view.selected} />}
      </>}
      <Group justify="flex-end"><Button variant="default" onClick={close}>Close</Button></Group>
    </Stack>
  </Drawer>;
}
