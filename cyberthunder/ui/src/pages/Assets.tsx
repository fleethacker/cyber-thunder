// Assets: the inventory is the scope guardrail. Scope changes ask for a reason and are audited.
import { ActionIcon, Badge, Button, Drawer, Group, Menu, Paper, ScrollArea, Stack, Switch, Table, Text } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { IconDots, IconPencil, IconPlus, IconTrash, IconZoomScan } from '@tabler/icons-react';
import { useMemo, useState } from 'react';
import { api, errorText } from '../api/client';
import type { AssetFacts, Severity, Target } from '../api/types';
import { ConfirmReasonModal } from '../components/ConfirmReasonModal';
import { DiscoveryPanel } from '../components/DiscoveryPanel';
import { AssetIcon, AsyncView, Empty, ErrorBox, JsonView, Loading, Mono, PageTitle, SeverityBadge, SimulatedBadge } from '../components/common';
import { TargetForm } from '../components/TargetForm';
import { fmtAgo } from '../lib/format';
import { useAsync } from '../lib/hooks';

type Counts = Record<string, Partial<Record<Severity, number>>>;

export default function Assets() {
  const st = useAsync(async () => (await api.targets()).targets, []);
  const open = useAsync(async () => (await api.findings({ status: 'open', limit: 5000 })).findings, []);
  const [form, setForm] = useState<{ open: boolean; target: Target | null }>({ open: false, target: null });
  const [scopeFor, setScopeFor] = useState<Target | null>(null);
  const [removeFor, setRemoveFor] = useState<Target | null>(null);
  const [modalError, setModalError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [facts, setFacts] = useState<{ target: Target; data?: AssetFacts; error?: string } | null>(null);
  const [loadingDemo, setLoadingDemo] = useState(false);

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
    if (!scopeFor) return;
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
      setBusy(false);
    }
  };

  const remove = async () => {
    if (!removeFor) return;
    setBusy(true);
    setModalError(null);
    try {
      await api.removeTarget(removeFor.id);
      setRemoveFor(null);
      await st.reload();
    } catch (e) {
      setModalError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  const discover = async (t: Target) => {
    setFacts({ target: t });
    try {
      setFacts({ target: t, data: await api.discover(t.id) });
    } catch (e) {
      setFacts({ target: t, error: errorText(e) });
    }
  };

  const loadDemo = async () => {
    setLoadingDemo(true);
    try {
      await api.demoLoad();
      notifications.show({ message: 'Simulated range loaded' });
      await st.reload();
    } catch (e) {
      notifications.show({ color: 'red', title: 'Refused', message: errorText(e) });
    } finally {
      setLoadingDemo(false);
    }
  };

  return (
    <Stack gap="md">
      <PageTitle
        title="Assets"
        subtitle="The inventory is the scope: the agent only touches in-scope assets listed here."
        right={<>
          <Button leftSection={<IconPlus size={16} />} onClick={() => setForm({ open: true, target: null })}>Add asset</Button>
          <Button variant="light" onClick={() => { void st.reload(); void open.reload(); }} loading={st.loading}>Refresh</Button>
        </>}
      />
      <AsyncView
        state={st}
        what="Loading inventory"
        isEmpty={(d) => d.length === 0}
        empty={
          <Empty title="No assets in the inventory" action={<Button loading={loadingDemo} onClick={() => void loadDemo()}>Load simulated range</Button>}>
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
                          <Switch checked={t.in_scope} onChange={() => { setModalError(null); setScopeFor(t); }} aria-label={`Scope for ${t.name}`} color="teal" />
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
                            <Button size="xs" variant="light" leftSection={<IconZoomScan size={14} />} disabled={!t.in_scope} onClick={() => void discover(t)}>Discover</Button>
                            <Menu position="bottom-end">
                              <Menu.Target><ActionIcon variant="subtle" aria-label="More"><IconDots size={16} /></ActionIcon></Menu.Target>
                              <Menu.Dropdown>
                                <Menu.Item leftSection={<IconPencil size={14} />} onClick={() => setForm({ open: true, target: t })}>Edit</Menu.Item>
                                <Menu.Item color="red" leftSection={<IconTrash size={14} />} onClick={() => { setModalError(null); setRemoveFor(t); }}>Remove</Menu.Item>
                              </Menu.Dropdown>
                            </Menu>
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

      <DiscoveryPanel />

      <TargetForm opened={form.open} initial={form.target} onClose={() => setForm({ open: false, target: null })} onSaved={() => void st.reload()} />
      <ConfirmReasonModal
        opened={!!scopeFor}
        onClose={() => setScopeFor(null)}
        title={scopeFor?.in_scope ? `Remove ${scopeFor?.name} from scope` : `Put ${scopeFor?.name} in scope`}
        body={scopeFor?.in_scope ? 'The agent will stop scanning or changing this asset.' : 'The agent may scan this asset and, with approval, change it.'}
        reasonRequired
        reasonHint="Required: kept in the asset notes; the scope change itself is audited (scope.change)"
        confirmLabel={scopeFor?.in_scope ? 'Remove from scope' : 'Put in scope'}
        confirmColor={scopeFor?.in_scope ? 'orange' : 'teal'}
        busy={busy}
        error={modalError}
        onConfirm={(r) => void changeScope(r)}
      />
      <ConfirmReasonModal
        opened={!!removeFor}
        onClose={() => setRemoveFor(null)}
        title={`Remove ${removeFor?.name} from the inventory`}
        body="The asset leaves the inventory (and the scope). Its past findings and audit records stay. Audited as inventory.remove."
        noReason
        confirmLabel="Remove"
        confirmColor="red"
        busy={busy}
        error={modalError}
        onConfirm={() => void remove()}
      />
      <Drawer opened={!!facts} onClose={() => setFacts(null)} position="right" size="lg" title={<Text fw={700}>Asset facts: {facts?.target.name}</Text>}>
        {facts && (facts.error ? <ErrorBox error={facts.error} /> : facts.data ? <JsonView value={facts.data} maxHeight={700} /> : <Loading what="Discovering (read-only)" />)}
      </Drawer>
    </Stack>
  );
}
