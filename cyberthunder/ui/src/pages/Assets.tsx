// Assets: the inventory is the scope guardrail. Scope changes ask for a reason and are audited.
import { ActionIcon, Alert, Badge, Button, Drawer, Group, Menu, Paper, ScrollArea, Stack, Switch, Table, Text } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { IconDots, IconPencil, IconPlus, IconTrash, IconZoomScan } from '@tabler/icons-react';
import { useMemo, useRef, useState } from 'react';
import { api, errorText } from '../api/client';
import { authorityRevision } from '../api/identity';
import type { AssetFacts, Severity, Target } from '../api/types';
import { PermissionButton, PermissionConfirm, PermissionGate, usePermissions } from '../components/PermissionGate';
import { DiscoveryPanel } from '../components/DiscoveryPanel';
import { AssetIcon, AsyncView, Empty, ErrorBox, JsonView, Loading, Mono, PageTitle, SeverityBadge, SimulatedBadge } from '../components/common';
import { TargetForm } from '../components/TargetForm';
import { HostSetup } from '../components/HostSetup';
import { isVsphereTarget, VsphereInventory } from '../components/VsphereInventory';
import { useSetupAccess } from '../components/setupAccess';
import { fmtAgo } from '../lib/format';
import { useAsync } from '../lib/hooks';

type Counts = Record<string, Partial<Record<Severity, number>>>;

export default function Assets() {
  const st = useAsync(async () => (await api.targets()).targets, []);
  const open = useAsync(async () => (await api.findings({ status: 'open', limit: 5000 })).findings, []);
  const [form, setForm] = useState<{ open: boolean; target: Target | null; defaults?: Partial<Target> }>({ open: false, target: null });
  const [hostSetup, setHostSetup] = useState(false);
  const [scopeFor, setScopeFor] = useState<Target | null>(null);
  const [removeFor, setRemoveFor] = useState<Target | null>(null);
  const [modalError, setModalError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [facts, setFacts] = useState<{ target: Target; data?: AssetFacts; error?: string } | null>(null);
  const [vsphereFor, setVsphereFor] = useState<{ id: string; authority: number } | null>(null);
  const [loadingDemo, setLoadingDemo] = useState(false);
  const blocked = useSetupAccess();
  const permission = usePermissions();
  const viewAuthority = authorityRevision();
  const inFlight = useRef(false);

  const counts = useMemo(() => {
    const c: Counts = {};
    for (const f of open.data ?? []) {
      const k = f.host;
      c[k] = c[k] ?? {};
      c[k][f.severity] = (c[k][f.severity] ?? 0) + 1;
    }
    return c;
  }, [open.data]);

  const changeScope = async (reason: string) => {
    if (!permission.can('admin') || !scopeFor || !reason.trim() || blocked || inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setModalError(null);
    try {
      const stamp = `[${new Date().toISOString().slice(0, 16)}Z] scope ${scopeFor.in_scope ? 'removed' : 'granted'}: ${reason}`;
      const notes = scopeFor.notes ? `${scopeFor.notes}\n${stamp}` : stamp;
      await api.updateTarget(scopeFor.id, { in_scope: !scopeFor.in_scope, notes });
      notifications.show({ message: `${scopeFor.name} ${scopeFor.in_scope ? 'removed from' : 'added to'} scope` });
      setScopeFor(null);
      await st.reload();
    } catch (e) {
      setModalError(errorText(e));
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  };

  const remove = async () => {
    if (!permission.can('admin') || !removeFor || blocked || inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setModalError(null);
    try {
      await api.removeTarget(removeFor.id);
      setRemoveFor(null);
      await st.reload();
    } catch (e) {
      setModalError(errorText(e));
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  };

  const discover = async (t: Target) => {
    if (!permission.can('discover') || blocked || !t.in_scope) return;
    setFacts({ target: t });
    try {
      setFacts({ target: t, data: await api.discover(t.id) });
    } catch (e) {
      setFacts({ target: t, error: errorText(e) });
    }
  };

  const loadDemo = async () => {
    if (!permission.can('admin') || blocked || inFlight.current) return;
    inFlight.current = true;
    setLoadingDemo(true);
    try {
      await api.demoLoad();
      notifications.show({ message: 'Simulated range loaded' });
      await st.reload();
    } catch (e) {
      notifications.show({ color: 'red', title: 'Refused', message: errorText(e) });
    } finally {
      inFlight.current = false;
      setLoadingDemo(false);
    }
  };

  return (
    <Stack gap="md">
      <PageTitle
        title="Assets"
        subtitle="Only explicitly authorized inventory assets may be scanned or changed with approval. Discovery search ranges are separate."
        right={<>
          <PermissionButton action="admin" variant="light" onClick={() => { if (permission.can('admin')) setHostSetup(true); }}>Set up deployment host</PermissionButton>
          <PermissionButton action="admin" leftSection={<IconPlus size={16} />} disabled={!!blocked} onClick={() => { if (permission.can('admin')) setForm({ open: true, target: null }); }}>Add asset</PermissionButton>
          <Button variant="light" onClick={() => { void st.reload(); void open.reload(); }} loading={st.loading}>Refresh</Button>
        </>}
      />
      {blocked && <Alert color="yellow">{blocked}</Alert>}
      <AsyncView
        state={st}
        what="Loading inventory"
        isEmpty={(d) => d.length === 0}
        empty={
          <Empty title="No assets in the inventory" action={<PermissionButton action="admin" loading={loadingDemo} disabled={!!blocked} onClick={() => void loadDemo()}>Load simulated range</PermissionButton>}>
            Add assets by hand, or load the simulated range for a demonstration.
          </Empty>
        }
      >
        {(targets) => (
          <Paper withBorder radius="md">
            <ScrollArea>
              <Table striped highlightOnHover verticalSpacing="sm" miw={960}>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>Name</Table.Th><Table.Th>Type</Table.Th><Table.Th>Transport</Table.Th><Table.Th>Address</Table.Th>
                    <Table.Th>In scope</Table.Th><Table.Th>Last scan</Table.Th><Table.Th>Open findings</Table.Th><Table.Th />
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {targets.map((t) => {
                    const c = counts[t.id] ?? counts[t.name] ?? {};
                    return (
                      <Table.Tr key={t.id}>
                        <Table.Td>
                          <Group gap={6} wrap="nowrap">
                            <AssetIcon type={t.asset_type} />
                            <Stack gap={0}><Text size="sm" fw={600}>{t.name}</Text><Mono>{t.id}</Mono></Stack>
                            <SimulatedBadge simulated={t.simulated} />
                          </Group>
                        </Table.Td>
                        <Table.Td><Badge variant="outline" color="gray">{t.asset_type}</Badge></Table.Td>
                        <Table.Td><Text size="sm">{t.transport}</Text></Table.Td>
                        <Table.Td><Mono>{t.address ? `${t.address}${t.port ? `:${t.port}` : ''}` : '-'}</Mono></Table.Td>
                        <Table.Td>
                          <PermissionGate allowed={permission.can('admin')} reason={permission.reason('admin') || ''}><Switch checked={t.in_scope} disabled={!!blocked || busy} onChange={() => { if (permission.can('admin')) { setModalError(null); setScopeFor(t); } }} aria-label={`Scope for ${t.name}`} color="teal" /></PermissionGate>
                        </Table.Td>
                        <Table.Td><Text size="sm">{fmtAgo(t.last_scan)}</Text></Table.Td>
                        <Table.Td>
                          <Group gap={4}>
                            {(['high', 'medium', 'low'] as const).map((s) => (
                              <Group gap={2} key={s}><SeverityBadge severity={s} size="xs" /><Text size="sm" fw={600}>{c[s] ?? 0}</Text></Group>
                            ))}
                          </Group>
                        </Table.Td>
                        <Table.Td>
                          <Group gap={4} wrap="nowrap">
                            {isVsphereTarget(t) ? <PermissionButton action="read" size="xs" variant="light" onClick={() => {
                              if (permission.can('read') && viewAuthority === authorityRevision()) setVsphereFor({ id: t.id, authority: viewAuthority });
                            }}>View vSphere inventory</PermissionButton> :
                              <PermissionButton action="discover" size="xs" variant="light" leftSection={<IconZoomScan size={14} />} disabled={!!blocked || !t.in_scope} onClick={() => void discover(t)}>Read asset facts</PermissionButton>}
                            {permission.can('admin') ? <Menu position="bottom-end">
                              <Menu.Target><ActionIcon variant="subtle" aria-label="More"><IconDots size={16} /></ActionIcon></Menu.Target>
                              <Menu.Dropdown>
                                <Menu.Item disabled={!!blocked || busy} leftSection={<IconPencil size={14} />} onClick={() => { if (permission.can('admin')) setForm({ open: true, target: t }); }}>Edit</Menu.Item>
                                <Menu.Item disabled={!!blocked || busy} color="red" leftSection={<IconTrash size={14} />} onClick={() => { if (permission.can('admin')) { setModalError(null); setRemoveFor(t); } }}>Remove</Menu.Item>
                              </Menu.Dropdown>
                            </Menu> : <PermissionGate allowed={false} reason={permission.reason('admin') || ''}>
                              <ActionIcon variant="subtle" aria-label={`Edit or remove ${t.name}`}><IconDots size={16} /></ActionIcon>
                            </PermissionGate>}
                          </Group>
                        </Table.Td>
                      </Table.Tr>
                    );
                  })}
                </Table.Tbody>
              </Table>
            </ScrollArea>
          </Paper>
        )}
      </AsyncView>
      {open.error && <ErrorBox error={`Open finding counts unavailable: ${open.error}`} />}

      <DiscoveryPanel onInventoryChanged={() => void st.reload()} />
      <VsphereInventory target={vsphereFor?.authority === authorityRevision()
        ? st.data?.find(t => t.id === vsphereFor.id && isVsphereTarget(t)) ?? null : null}
        blocked={blocked} onClose={() => setVsphereFor(null)} />

      <HostSetup opened={hostSetup && permission.can('admin')} onClose={() => setHostSetup(false)} onSaved={() => void st.reload()}
        onUseLocal={(defaults) => { setHostSetup(false); setForm({ open: true, target: null, defaults }); }} />
      <TargetForm opened={form.open} initial={form.target} defaults={form.defaults} onClose={() => setForm({ open: false, target: null })} onSaved={() => void st.reload()} />
      <PermissionConfirm action="admin"
        opened={!!scopeFor}
        onClose={() => { if (!inFlight.current) setScopeFor(null); }}
        title={scopeFor?.in_scope ? `Remove ${scopeFor?.name} from scope` : `Put ${scopeFor?.name} in scope`}
        body={scopeFor?.in_scope ? 'The agent will stop scanning or changing this asset. Discovery search ranges are unchanged.' : 'Authorize scans and approved changes for this inventory asset only. This does not start a scan or authorize other addresses in its discovery range.'}
        reasonRequired
        reasonHint="Required: kept in the asset notes; the scope change itself is audited (scope.change)"
        confirmLabel={scopeFor?.in_scope ? 'Remove from scope' : 'Put in scope'}
        confirmColor={scopeFor?.in_scope ? 'orange' : 'teal'}
        busy={busy}
        error={modalError ?? blocked}
        onConfirm={(r) => void changeScope(r)}
      />
      <PermissionConfirm action="admin"
        opened={!!removeFor}
        onClose={() => { if (!inFlight.current) setRemoveFor(null); }}
        title={`Remove ${removeFor?.name} from the inventory`}
        body="The asset leaves the inventory (and the scope). Its past findings and audit records stay. Audited as inventory.remove."
        noReason
        confirmLabel="Remove"
        confirmColor="red"
        busy={busy}
        error={modalError ?? blocked}
        onConfirm={() => void remove()}
      />
      <Drawer opened={!!facts} onClose={() => setFacts(null)} position="right" size="lg" title={<Text fw={700}>Asset facts: {facts?.target.name}</Text>}>
        {facts && (facts.error ? <ErrorBox error={facts.error} /> : facts.data ? <JsonView value={facts.data} maxHeight={700} /> : <Loading what="Discovering (read-only)" />)}
      </Drawer>
    </Stack>
  );
}
