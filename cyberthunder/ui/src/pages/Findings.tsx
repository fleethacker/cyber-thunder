// Findings: filterable table of the current findings view; click a row for the detail drawer.
// Pages of 200 rows (server-side limit/offset) keep the DOM small instead of virtualizing.
import { Badge, Button, Group, MultiSelect, Pagination, Paper, ScrollArea, Stack, Table, Text, TextInput, Tooltip } from '@mantine/core';
import { useDebouncedValue } from '@mantine/hooks';
import { notifications } from '@mantine/notifications';
import { IconCheck, IconMinus, IconSearch, IconSparkles } from '@tabler/icons-react';
import { useState } from 'react';
import { api, errorText } from '../api/client';
import { ASSET_TYPES } from '../api/types';
import { AssetIcon, AsyncView, Empty, Mono, PageTitle, SeverityBadge, StateBadge, StatusBadge } from '../components/common';
import { FindingDrawer } from '../components/FindingDrawer';
import { useAsync, useLocalPref } from '../lib/hooks';

const PAGE = 200;
const STATUSES = ['open', 'not_a_finding', 'not_applicable', 'not_reviewed', 'error'];
const SOURCES = ['openscap', 'scc', 'evaluate-stig', 'powerstig', 'hunt', 'cve', 'iavm'];

function Yes({ v, tip }: { v: boolean; tip: string }) {
  return (
    <Tooltip label={tip}>
      {v ? <IconCheck size={16} color="var(--mantine-color-green-6)" /> : <IconMinus size={16} opacity={0.4} />}
    </Tooltip>
  );
}

export default function Findings() {
  const [q, setQ] = useState('');
  const [dq] = useDebouncedValue(q, 300);
  const [status, setStatus] = useLocalPref<string[]>('ct.f.status', ['open']);
  const [severity, setSeverity] = useLocalPref<string[]>('ct.f.sev', []);
  const [source, setSource] = useLocalPref<string[]>('ct.f.src', []);
  const [assetType, setAssetType] = useLocalPref<string[]>('ct.f.type', []);
  const [host, setHost] = useLocalPref<string[]>('ct.f.host', []);
  const [page, setPage] = useState(1);
  const [drawer, setDrawer] = useState<string | null>(null);
  const [explaining, setExplaining] = useState(false);

  const key = [dq, status.join(), severity.join(), source.join(), assetType.join(), host.join(), page];
  const st = useAsync(() => api.findings({
    q: dq, status: status.join(','), severity: severity.join(','), source: source.join(','),
    asset_type: assetType.join(','), host: host.join(','), limit: PAGE, offset: (page - 1) * PAGE,
  }), key);
  const hosts = st.data?.summary?.hosts ?? [];

  const explainAll = async () => {
    setExplaining(true);
    try {
      const r = await api.explainAll();
      notifications.show({ message: `${r.queued} explanations queued on the local model` });
    } catch (e) {
      notifications.show({ color: 'red', title: 'Refused', message: errorText(e) });
    } finally {
      setExplaining(false);
    }
  };

  const reset = (fn: (v: string[]) => void) => (v: string[]) => { setPage(1); fn(v); };

  return (
    <Stack gap="md">
      <PageTitle
        title="Findings"
        subtitle={st.data ? `${st.data.total} matching · scan ${st.data.scan_id ?? '-'}` : undefined}
        right={<>
          <Button variant="light" leftSection={<IconSparkles size={16} />} loading={explaining} onClick={() => void explainAll()}>Precompute explanations</Button>
          <Button variant="light" onClick={() => void st.reload()} loading={st.loading}>Refresh</Button>
        </>}
      />
      {st.data?.summary && (
        <Group gap="xs">
          {(['high', 'medium', 'low'] as const).map((s) => (
            <Group gap={4} key={s}><SeverityBadge severity={s} /><Text fw={700}>{st.data?.summary?.open_by_severity[s] ?? 0}</Text><Text size="sm" c="dimmed">open</Text></Group>
          ))}
        </Group>
      )}
      <Group gap="sm" align="flex-end" wrap="wrap">
        <TextInput label="Search" placeholder="title, rule id, STIG id" leftSection={<IconSearch size={16} />} value={q} onChange={(e) => { setPage(1); setQ(e.currentTarget.value); }} w={260} />
        <MultiSelect label="Status" data={STATUSES} value={status} onChange={reset(setStatus)} clearable w={200} placeholder="All" />
        <MultiSelect label="Severity" data={[{ value: 'high', label: 'CAT I' }, { value: 'medium', label: 'CAT II' }, { value: 'low', label: 'CAT III' }, { value: 'info', label: 'Info' }]} value={severity} onChange={reset(setSeverity)} clearable w={180} placeholder="All" />
        <MultiSelect label="Host" data={hosts} value={host} onChange={reset(setHost)} clearable searchable w={200} placeholder="All" />
        <MultiSelect label="Asset type" data={ASSET_TYPES} value={assetType} onChange={reset(setAssetType)} clearable w={180} placeholder="All" />
        <MultiSelect label="Source" data={SOURCES} value={source} onChange={reset(setSource)} clearable w={180} placeholder="All" />
      </Group>

      <AsyncView
        state={st}
        what="Loading findings"
        isEmpty={(d) => d.findings.length === 0}
        empty={<Empty title="No findings match">Run a scan, or clear the filters.</Empty>}
      >
        {(d) => (
          <Paper withBorder radius="md">
            <ScrollArea>
              <Table striped highlightOnHover verticalSpacing="xs" miw={1000}>
                <Table.Thead>
                  <Table.Tr>
                    <Table.Th>CAT</Table.Th><Table.Th>Status</Table.Th><Table.Th>Host</Table.Th><Table.Th>Source</Table.Th>
                    <Table.Th>Rule / STIG ID</Table.Th><Table.Th>Title</Table.Th><Table.Th>Fix</Table.Th><Table.Th>Explained</Table.Th><Table.Th>Proposal</Table.Th>
                  </Table.Tr>
                </Table.Thead>
                <Table.Tbody>
                  {d.findings.map((f) => (
                    <Table.Tr key={f.id} onClick={() => setDrawer(f.id)} style={{ cursor: 'pointer' }}>
                      <Table.Td><SeverityBadge severity={f.severity} size="sm" /></Table.Td>
                      <Table.Td><StatusBadge status={f.status} /></Table.Td>
                      <Table.Td><Group gap={4} wrap="nowrap"><AssetIcon type={f.asset_type} size={14} /><Text size="sm">{f.host}</Text></Group></Table.Td>
                      <Table.Td><Badge variant="outline" color="gray" size="sm">{f.source}</Badge></Table.Td>
                      <Table.Td><Mono>{f.rule_version ?? f.rule_id}</Mono></Table.Td>
                      <Table.Td><Text size="sm" lineClamp={2}>{f.title}</Text></Table.Td>
                      <Table.Td><Yes v={!!f.fix} tip={f.fix ? f.fix.fix_ref : 'no library fix'} /></Table.Td>
                      <Table.Td><Yes v={!!f.explanation} tip={f.explanation ? 'explanation ready' : 'not yet explained'} /></Table.Td>
                      <Table.Td>{f.proposal ? <StateBadge state={f.proposal.state} /> : <Text size="sm" c="dimmed">-</Text>}</Table.Td>
                    </Table.Tr>
                  ))}
                </Table.Tbody>
              </Table>
            </ScrollArea>
            {d.total > PAGE && (
              <Group justify="center" p="sm"><Pagination total={Math.ceil(d.total / PAGE)} value={page} onChange={setPage} /></Group>
            )}
          </Paper>
        )}
      </AsyncView>
      <FindingDrawer findingId={drawer} onClose={() => setDrawer(null)} onProposed={() => void st.reload()} />
    </Stack>
  );
}
