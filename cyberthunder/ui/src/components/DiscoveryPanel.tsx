// Discovery panel on the Assets page (docs/DISCOVERY.md, "Assets page: Discovery panel").
// Scopes bar, sweep with mode select, candidate table with new/known/changed/missing badges, Accept and
// Ignore decisions, and the findings the latest sweep raised. Discovery itself is read-only: the only way a
// device reaches the inventory is Accept, which needs a named operator, an explicit scope decision and a reason.
import {
  Alert, Badge, Button, Card, Group, Modal, MultiSelect, Radio, ScrollArea, SegmentedControl, Select, Stack, Table, Tabs,
  Text, TextInput, Textarea, Tooltip,
} from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { IconChevronDown, IconChevronRight, IconRadar, IconRefresh } from '@tabler/icons-react';
import { Fragment, useEffect, useRef, useState } from 'react';
import { api, errorText } from '../api/client';
import {
  ASSET_TYPES, DISCOVERY_MODES, TRANSPORTS,
  type DiscoveredAsset, type DiscoveryMode, type DiscoveryRun, type DiscoveryStatus,
} from '../api/types';
import { fmtAgo } from '../lib/format';
import { useAsync, useInterval } from '../lib/hooks';
import { ConfirmReasonModal } from './ConfirmReasonModal';
import { ErrorBox, Loading, Mono, SeverityBadge } from './common';
import { useSetupAccess } from './setupAccess';
import { ScopeEditor } from './ScopeEditor';

const DEFAULT_TRANSPORT: Record<string, string> = {
  linux: 'ssh', windows: 'winrm', cisco_ios: 'ssh', kubernetes: 'kubeconfig', containers: 'ssh',
};
const STATUS_COLOR: Record<string, string> = { new: 'red', known: 'teal', missing: 'orange', ignored: 'gray' };
const RUN_COLOR: Record<string, string> = { running: 'blue', finished: 'teal', partial: 'yellow', failed: 'red', stopped: 'orange' };

function noteChips(a: DiscoveredAsset): string[] {
  const out = new Set<string>();
  for (const e of [...a.evidence, a.notes]) {
    for (const m of (e ?? '').matchAll(/virtual:[a-z0-9_-]+/gi)) out.add(m[0]);
    if (/consumer\/iot device/i.test(e ?? '')) out.add('consumer/iot device');
  }
  return [...out];
}

function changeText(a: DiscoveredAsset): string {
  return a.changes.map((c) => `${c.kind}${c.detail ? `: ${c.detail}` : ''}`).join('; ');
}

// -- accept ------------------------------------------------------------------------------------------
export function AcceptModal({ asset, onClose, onAccepted }: { asset: DiscoveredAsset | null; onClose: () => void; onAccepted: () => void }) {
  const [name, setName] = useState('');
  const [type, setType] = useState<string | null>(null);
  const [transport, setTransport] = useState<string | null>(null);
  const [username, setUsername] = useState('');
  const [scope, setScope] = useState('');
  const [reason, setReason] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const blocked = useSetupAccess();
  const inFlight = useRef(false);
  // A device seen by the simulated sweep exists only in the emulator, so it can only become a simulated target.
  const simulated = !!asset?.facts?.simulated;
  useEffect(() => {
    if (!asset) return;
    const guess = (ASSET_TYPES as string[]).includes(asset.asset_type_guess) ? asset.asset_type_guess : null;
    setName(asset.hostname ?? asset.address ?? '');
    setType(guess);
    setTransport(simulated ? 'simulated' : guess ? DEFAULT_TRANSPORT[guess] ?? 'ssh' : null);
    setUsername('');
    setScope(''); // no default: the operator decides in or out every time
    setReason('');
    setError(null);
  }, [asset, simulated]);
  if (!asset) return null;
  const ready = !!type && !!transport && !!scope && !!reason.trim() && !!name.trim();
  const accept = async () => {
    if (!ready || blocked || inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setError(null);
    try {
      const t = await api.acceptAsset(asset.id, {
        name: name.trim(), asset_type: type ?? undefined, transport: transport ?? undefined,
        username: username.trim() || undefined, in_scope: scope === 'in', reason: reason.trim(),
      });
      notifications.show({ color: 'green', message: `${t.name} added to the inventory (${t.in_scope ? 'in scope' : 'out of scope'})` });
      onAccepted();
      onClose();
    } catch (e) {
      setError(errorText(e));
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  };
  return (
    <Modal opened onClose={() => { if (!inFlight.current) onClose(); }} closeOnClickOutside={!busy} closeOnEscape={!busy} withCloseButton={!busy}
      title={<Text fw={700}>Accept {asset.address ?? asset.id} into the inventory</Text>} centered size="lg">
      <Stack>
        <Group grow>
          <TextInput label="Name" required value={name} onChange={(e) => setName(e.currentTarget.value)} />
          <Select label="Asset type" required data={ASSET_TYPES} value={type}
            placeholder={asset.asset_type_guess === 'unknown' ? 'guess is unknown: choose one' : undefined}
            onChange={(v) => { setType(v); if (v && !simulated) setTransport(DEFAULT_TRANSPORT[v] ?? 'ssh'); }} />
        </Group>
        <Group grow>
          <Select label="Transport" data={simulated ? ['simulated'] : [...TRANSPORTS]} value={transport} onChange={setTransport}
            description={simulated ? 'seen by the simulated sweep' : undefined} />
          <TextInput label="Username" value={username} onChange={(e) => setUsername(e.currentTarget.value)} />
        </Group>
        <Radio.Group label="Inventory authorization" description="A search range does not authorize candidates. Choose whether this asset permits scans and approved changes, or is recorded only." required value={scope} onChange={setScope}>
          <Group mt="xs">
            <Radio value="in" label="In scope" />
            <Radio value="out" label="Out of scope" />
          </Group>
        </Radio.Group>
        <Textarea label="Reason" required placeholder="who owns it and why it belongs here (written to the audit log)" value={reason} onChange={(e) => setReason(e.currentTarget.value)} />
        <Text size="sm" c="dimmed">
          This adds the asset to the inventory
          {scope === 'in' ? ' and allows scans of it.' : scope === 'out' ? '. It stays out of every scan until someone puts it in scope.' : '.'}
        </Text>
        <Text size="sm">Acceptance does not start a scan. Connection declarations do not verify credentials, reachability or privileges.</Text>
        {blocked && <Alert color="yellow">{blocked}</Alert>}
        {error && <Alert color="red">{error}</Alert>}
        <Group justify="flex-end">
          <Button variant="default" disabled={busy} onClick={() => { if (!inFlight.current) onClose(); }}>Cancel</Button>
          <Button disabled={!ready || !!blocked || busy} loading={busy} onClick={() => void accept()}>Accept</Button>
        </Group>
      </Stack>
    </Modal>
  );
}

// -- candidate table ---------------------------------------------------------------------------------
function AssetRow({ a, onAccept, onIgnore }: { a: DiscoveredAsset; onAccept: () => void; onIgnore: () => void }) {
  const [open, setOpen] = useState(false);
  const chips = noteChips(a);
  return (
    <Fragment>
      <Table.Tr>
        <Table.Td>
          <Button variant="subtle" size="compact-xs" onClick={() => setOpen((o) => !o)} aria-label="Show evidence">
            {open ? <IconChevronDown size={14} /> : <IconChevronRight size={14} />}
          </Button>
        </Table.Td>
        <Table.Td>
          <Group gap={4} wrap="nowrap">
            <Badge color={STATUS_COLOR[a.status] ?? 'gray'} variant="light">{a.status}</Badge>
            {a.changes.length > 0 && (
              <Tooltip label={changeText(a)} multiline w={320}><Badge color="yellow" variant="light">changed</Badge></Tooltip>
            )}
          </Group>
        </Table.Td>
        <Table.Td><Mono>{a.address ?? '-'}</Mono></Table.Td>
        <Table.Td><Text size="sm">{a.mac ?? '-'}</Text><Text size="xs" c="dimmed">{a.vendor ?? ''}</Text></Table.Td>
        <Table.Td>{a.hostname ?? '-'}</Table.Td>
        <Table.Td><Text size="sm">{a.asset_type_guess}</Text><Text size="xs" c="dimmed">{Math.round(a.confidence * 100)}%</Text></Table.Td>
        <Table.Td><Text size="xs" ff="monospace">{a.open_ports.map((p) => `${p.port}/${p.proto}`).join(' ') || '-'}</Text></Table.Td>
        <Table.Td><Text size="xs">{a.sources.join(', ')}</Text></Table.Td>
        <Table.Td><Group gap={4}>{chips.map((c) => <Badge key={c} variant="outline" color="gray" tt="none" size="sm">{c}</Badge>)}</Group></Table.Td>
        <Table.Td>
          <Group gap={4} wrap="nowrap">
            {a.status === 'new' && <Button size="compact-sm" onClick={onAccept}>Accept</Button>}
            {(a.status === 'new' || a.status === 'missing') && (
              <Button size="compact-sm" variant="light" color="gray" onClick={onIgnore}>Ignore</Button>
            )}
          </Group>
        </Table.Td>
      </Table.Tr>
      {open && (
        <Table.Tr>
          <Table.Td colSpan={10}>
            <Stack gap={4}>
              {a.os_guess && <Text size="sm">OS guess: {a.os_guess}{a.os_accuracy ? ` (${a.os_accuracy}%)` : ''}</Text>}
              {a.changes.length > 0 && <Text size="sm">Changes: {changeText(a)}</Text>}
              {a.open_ports.length > 0 && (
                <Text size="sm">Ports: {a.open_ports.map((p) => `${p.port}/${p.proto} ${p.service} ${p.product} ${p.version}`.trim()).join(', ')}</Text>
              )}
              <Text size="sm" fw={600}>Evidence</Text>
              {a.evidence.map((e, i) => <Text key={i} size="xs" ff="monospace">{e}</Text>)}
              <Text size="xs" c="dimmed">id {a.id} · first seen {fmtAgo(a.first_seen)} · last seen {fmtAgo(a.last_seen)}</Text>
            </Stack>
          </Table.Td>
        </Table.Tr>
      )}
    </Fragment>
  );
}

function RunSummary({ run }: { run: DiscoveryRun }) {
  return (
    <Stack gap={4}>
      <Group gap="xs">
        <Text size="sm">Sweep <Mono>{run.id}</Mono> ({run.mode}) by {run.requested_by || '-'}</Text>
        <Badge color={RUN_COLOR[run.status] ?? 'gray'} variant="light">{run.status}</Badge>
      </Group>
      <Text size="sm">seen {run.hosts_seen} · new {run.new} · known {run.known} · changed {run.changed} · missing {run.missing}</Text>
      {run.errors.map((e, i) => <Text key={i} size="xs" c="orange">{e}</Text>)}
    </Stack>
  );
}

export function DiscoveryPanel({ onInventoryChanged }: { onInventoryChanged?: () => void }) {
  const blocked = useSetupAccess();
  const sweepFlight = useRef(false);
  const ignoreFlight = useRef(false);
  const [starting, setStarting] = useState(false);
  const overview = useAsync(() => api.discovery(), []);
  const [statusFilter, setStatusFilter] = useState('all');
  const assets = useAsync(
    () => api.discoveredAssets(statusFilter === 'all' ? undefined : (statusFilter as DiscoveryStatus)),
    [statusFilter],
  );
  const findings = useAsync(() => api.discoveryFindings(), []);
  const [mode, setMode] = useState<DiscoveryMode | null>(null);
  const [subset, setSubset] = useState<string[]>([]);
  const [run, setRun] = useState<DiscoveryRun | null>(null);
  const [sweepError, setSweepError] = useState<string | null>(null);
  const [scopesOpen, setScopesOpen] = useState(false);
  const [acceptFor, setAcceptFor] = useState<DiscoveredAsset | null>(null);
  const [ignoreFor, setIgnoreFor] = useState<DiscoveredAsset | null>(null);
  const [ignoreErr, setIgnoreErr] = useState<string | null>(null);

  const scopes = overview.data?.scopes ?? [];
  const shownRun = run ?? overview.data?.last_run ?? null;
  // A saved scope means a real network; with none saved, the simulated enclave is all a sweep can see.
  const chosenMode: DiscoveryMode = mode ?? (scopes.length ? 'quick' : 'simulated');
  const running = run?.status === 'running';

  const refreshAll = () => { void overview.reload(); void assets.reload(); void findings.reload(); };

  useInterval(() => {
    if (!run || run.status !== 'running') return;
    api.discoveryRun(run.id).then((r) => {
      setRun(r);
      if (r.status !== 'running') refreshAll();
    }).catch((e) => {
      setSweepError(errorText(e));
      setRun(null);
    });
  }, 1000, running);

  const sweep = async () => {
    if (blocked || running || sweepFlight.current) return;
    sweepFlight.current = true; setStarting(true);
    setSweepError(null);
    try {
      setRun(await api.sweep(chosenMode, subset));
    } catch (e) {
      setSweepError(errorText(e));
    } finally {
      sweepFlight.current = false; setStarting(false);
    }
  };

  const ignore = async (reason: string) => {
    if (!ignoreFor || !reason.trim() || blocked || ignoreFlight.current) return;
    ignoreFlight.current = true;
    setIgnoreErr(null);
    try {
      await api.ignoreAsset(ignoreFor.id, reason);
      setIgnoreFor(null);
      refreshAll();
    } catch (e) {
      setIgnoreErr(errorText(e));
    } finally {
      ignoreFlight.current = false;
    }
  };

  return (
    <Card withBorder radius="md" padding="md">
      <Stack gap="sm">
        <Group justify="space-between">
          <Group gap="xs">
            <IconRadar size={18} />
            <Text fw={700}>Discovery</Text>
            {overview.data && Object.entries(overview.data.counts).map(([k, v]) => (
              <Badge key={k} color={STATUS_COLOR[k] ?? 'gray'} variant="light">{k} {v}</Badge>
            ))}
          </Group>
          <Button size="xs" variant="light" leftSection={<IconRefresh size={14} />} loading={overview.loading || assets.loading} onClick={refreshAll}>Refresh</Button>
        </Group>
        {overview.error && <ErrorBox error={overview.error} onRetry={() => void overview.reload()} />}
        <Text size="sm">Search ranges only limit discovery probes. They do not authorize any discovered address for scans or changes. Review and accept each inventory asset with an explicit scope decision.</Text>
        {blocked && <Alert color="yellow">{blocked}</Alert>}

        <Group gap="xs" align="center">
          <Text size="sm" fw={600}>Search ranges:</Text>
          {scopes.length === 0 && <Text size="sm" c="dimmed">none saved (a simulated sweep uses the demo enclave)</Text>}
          {scopes.map((s) => (
            <Tooltip key={s.cidr} label={`added by ${s.added_by || '-'} ${fmtAgo(s.added_at)}${s.reason ? `: ${s.reason}` : ''}`} multiline w={320}>
              <Badge variant="outline" tt="none" ff="monospace">{s.cidr}{s.allow_public ? ' (public)' : ''}</Badge>
            </Tooltip>
          ))}
          <Button size="compact-sm" variant="subtle" disabled={!overview.data || !!overview.error || overview.loading}
            onClick={() => { if (overview.data && !overview.error && !overview.loading) setScopesOpen(true); }}>Edit search ranges</Button>
        </Group>

        <Group gap="sm" align="flex-end">
          <Select label="Mode" data={[...DISCOVERY_MODES]} value={chosenMode} allowDeselect={false} w={140}
            onChange={(v) => setMode(v as DiscoveryMode)} />
          {scopes.length > 1 && (
            <MultiSelect label="Search ranges to sweep" data={scopes.map((s) => s.cidr)} value={subset} onChange={setSubset}
              placeholder="all saved" clearable w={260} />
          )}
          <Button leftSection={<IconRadar size={16} />} disabled={!!blocked || running || starting} loading={running || starting} onClick={() => void sweep()}>Run sweep</Button>
        </Group>
        {sweepError && <Alert color="red" title="Sweep refused">{sweepError}</Alert>}
        {shownRun && <RunSummary run={shownRun} />}

        <Tabs defaultValue="assets">
          <Tabs.List>
            <Tabs.Tab value="assets">Candidates</Tabs.Tab>
            <Tabs.Tab value="findings">Findings{findings.data ? ` (${findings.data.length})` : ''}</Tabs.Tab>
          </Tabs.List>
          <Tabs.Panel value="assets" pt="sm">
            <Stack gap="xs">
              <SegmentedControl size="xs" value={statusFilter} onChange={setStatusFilter}
                data={['all', 'new', 'known', 'missing', 'ignored']} style={{ alignSelf: 'flex-start' }} />
              {assets.error ? (
                <ErrorBox error={assets.error} onRetry={() => void assets.reload()} />
              ) : !assets.data ? (
                <Loading what="Loading discovered assets" />
              ) : assets.data.length === 0 ? (
                <Text size="sm" c="dimmed">No discovered assets{statusFilter !== 'all' ? ` with status ${statusFilter}` : ''}. Run a sweep.</Text>
              ) : (
                <ScrollArea>
                  <Table striped highlightOnHover verticalSpacing="xs">
                    <Table.Thead>
                      <Table.Tr>
                        <Table.Th /><Table.Th>Status</Table.Th><Table.Th>Address</Table.Th><Table.Th>MAC / vendor</Table.Th>
                        <Table.Th>Hostname</Table.Th><Table.Th>Type guess</Table.Th><Table.Th>Open ports</Table.Th>
                        <Table.Th>Sources</Table.Th><Table.Th>Notes</Table.Th><Table.Th />
                      </Table.Tr>
                    </Table.Thead>
                    <Table.Tbody>
                      {assets.data.map((a) => (
                        <AssetRow key={a.id} a={a} onAccept={() => setAcceptFor(a)}
                          onIgnore={() => { setIgnoreErr(null); setIgnoreFor(a); }} />
                      ))}
                    </Table.Tbody>
                  </Table>
                </ScrollArea>
              )}
            </Stack>
          </Tabs.Panel>
          <Tabs.Panel value="findings" pt="sm">
            {findings.error ? (
              <ErrorBox error={findings.error} onRetry={() => void findings.reload()} />
            ) : !findings.data ? (
              <Loading what="Loading discovery findings" />
            ) : findings.data.length === 0 ? (
              <Text size="sm" c="dimmed">The latest sweep raised no findings.</Text>
            ) : (
              <ScrollArea>
                <Table striped verticalSpacing="xs">
                  <Table.Thead>
                    <Table.Tr><Table.Th>Severity</Table.Th><Table.Th>Rule</Table.Th><Table.Th>Host</Table.Th><Table.Th>Title</Table.Th><Table.Th>Cites</Table.Th></Table.Tr>
                  </Table.Thead>
                  <Table.Tbody>
                    {findings.data.map((f) => (
                      <Table.Tr key={f.id}>
                        <Table.Td><SeverityBadge severity={f.severity} size="sm" /></Table.Td>
                        <Table.Td><Mono>{f.rule_id}</Mono></Table.Td>
                        <Table.Td><Mono>{f.host}</Mono></Table.Td>
                        <Table.Td><Text size="sm">{f.title}</Text></Table.Td>
                        <Table.Td><Text size="xs">{(f.references ?? []).map((r) => r.id).join(', ')}</Text></Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </ScrollArea>
            )}
          </Tabs.Panel>
        </Tabs>
      </Stack>

      <ScopeEditor opened={scopesOpen} current={scopes} onClose={() => setScopesOpen(false)} onSaved={() => void overview.reload()} />
      <AcceptModal asset={acceptFor} onClose={() => setAcceptFor(null)}
        onAccepted={() => { refreshAll(); onInventoryChanged?.(); }} />
      <ConfirmReasonModal
        opened={!!ignoreFor}
        title={`Ignore ${ignoreFor?.address ?? ignoreFor?.id ?? ''}`}
        body={<Text size="sm">Ignored devices stay ignored on later sweeps and drop out of discovery findings.</Text>}
        reasonRequired
        confirmLabel="Ignore"
        error={ignoreErr ?? blocked}
        onConfirm={(r) => void ignore(r)}
        onClose={() => setIgnoreFor(null)}
      />
    </Card>
  );
}
