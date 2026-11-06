// Filtering, facets and ordering are computed by the API before pagination.
import { ActionIcon, Badge, Button, Group, MultiSelect, Pagination, Paper, ScrollArea, Select, SimpleGrid, Stack, Table, Text, TextInput, Tooltip } from '@mantine/core';
import { useDebouncedValue } from '@mantine/hooks';
import { notifications } from '@mantine/notifications';
import { IconCheck, IconMinus, IconSearch, IconSparkles, IconX } from '@tabler/icons-react';
import { useEffect, useState } from 'react';
import { api, errorText } from '../api/client';
import type { FindingFacet, FindingsPage, FindingsQuery, FindingSort, SortDirection } from '../api/types';
import { AssetIcon, AsyncView, Empty, Mono, PageTitle, SeverityBadge, StateBadge } from '../components/common';
import { FindingDrawer } from '../components/FindingDrawer';
import { ConfidenceBadge, ReviewBadge } from '../components/FindingAssurance';
import { FindingReassessment } from '../components/FindingReassessment';
import { CONFIDENCE_LABELS, REVIEW_FILTER_LABELS } from '../lib/findingAssurance';
import { fmtTime, fmtZonedTime, statusColor } from '../lib/format';
import { useLocalPref } from '../lib/hooks';
import { findingResultLabel, findingRowHandlers } from '../lib/findingRow';

const PAGE = 200;
const LABELS: Record<string, string> = {
  stig: 'STIG', cve: 'CVE', hunt: 'Hunt', other: 'Other',
  high: 'CAT I · High', medium: 'CAT II · Medium', low: 'CAT III · Low', info: 'Info', unknown: 'Unknown',
  open: 'Failed / open', not_a_finding: 'Passed', not_applicable: 'Not applicable',
  not_reviewed: 'Not assessed', error: 'Collection error', __missing__: 'Not recorded',
};
const SORTS: { value: FindingSort; label: string }[] = [
  { value: 'default', label: 'Default priority' }, { value: 'severity', label: 'Severity' },
  { value: 'host', label: 'Machine' }, { value: 'asset_type', label: 'Asset type' },
  { value: 'category', label: 'Category' }, { value: 'title', label: 'Title' },
  { value: 'rule_id', label: 'Rule ID' }, { value: 'rule_version', label: 'STIG ID / rule version' }, { value: 'source', label: 'Source' },
  { value: 'collected_at', label: 'Observation time' }, { value: 'benchmark', label: 'Benchmark' },
  { value: 'benchmark_release', label: 'Release' },
  { value: 'confidence', label: 'Evidence confidence' }, { value: 'review', label: 'Human review' },
];

// Quote CSV values so names such as "Release 1, January" remain a single selection.
const csv = (values: string[]) => values.map((v) => `"${v.replace(/"/g, '""')}"`).join(',');

function Yes({ v, tip }: { v: boolean; tip: string }) {
  return <Tooltip label={tip}>{v ? <IconCheck size={16} color="var(--mantine-color-green-6)" /> : <IconMinus size={16} opacity={0.4} />}</Tooltip>;
}

export default function Findings() {
  const [q, setQ] = useLocalPref('ct.f.q', '');
  const [dq] = useDebouncedValue(q, 300);
  const [status, setStatus] = useLocalPref<string[]>('ct.f.status', ['open']);
  const [severity, setSeverity] = useLocalPref<string[]>('ct.f.sev', []);
  const [source, setSource] = useLocalPref<string[]>('ct.f.src', []);
  const [assetType, setAssetType] = useLocalPref<string[]>('ct.f.type', []);
  const [host, setHost] = useLocalPref<string[]>('ct.f.host', []);
  const [category, setCategory] = useLocalPref<string[]>('ct.f.category', []);
  const [benchmark, setBenchmark] = useLocalPref<string[]>('ct.f.benchmark', []);
  const [release, setRelease] = useLocalPref<string[]>('ct.f.release', []);
  const [confidence, setConfidence] = useLocalPref<string[]>('ct.f.confidence', []);
  const [review, setReview] = useLocalPref<string[]>('ct.f.review', []);
  const [sortBy, setSortBy] = useLocalPref<FindingSort>('ct.f.sort', 'default');
  const [sortDir, setSortDir] = useLocalPref<SortDirection>('ct.f.direction', 'asc');
  const [page, setPage] = useState(1);
  const [drawer, setDrawer] = useState<string | null>(null);
  const [reviewOpen, setReviewOpen] = useState(false);
  const [explaining, setExplaining] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [data, setData] = useState<FindingsPage>();
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  // Capability comes from server facets, including on an empty findings view.
  const confidenceAvailable = data?.facets?.confidence !== undefined;
  const reviewAvailable = data?.facets?.review !== undefined;
  const sortAvailable = (sortBy !== 'confidence' || confidenceAvailable) && (sortBy !== 'review' || reviewAvailable);
  const effectiveSort = sortAvailable ? sortBy : 'default';
  const query: FindingsQuery = {
    q: dq, status: csv(status), severity: csv(severity), source: csv(source), asset_type: csv(assetType),
    host: csv(host), category: csv(category), benchmark: csv(benchmark), benchmark_release: csv(release),
    confidence: confidenceAvailable ? csv(confidence) : undefined, review: reviewAvailable ? csv(review) : undefined,
    sort_by: effectiveSort, sort_dir: effectiveSort === 'default' ? 'asc' : sortDir, limit: PAGE, offset: (page - 1) * PAGE,
  };
  const queryKey = JSON.stringify(query);
  useEffect(() => {
    // A slower previous search must never replace the user's latest selection.
    let active = true;
    setLoading(true);
    setError(null);
    void api.findings(JSON.parse(queryKey) as FindingsQuery).then((result) => {
      if (!active) return;
      setData(result);
      setPage((p) => Math.min(p, Math.max(1, Math.ceil(result.total / PAGE))));
    }).catch((e: unknown) => { if (active) setError(errorText(e)); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [queryKey, refresh]);
  const reload = async () => { setRefresh((r) => r + 1); };
  const st = { data, error, loading, reload, setData };

  const axes: { key: FindingFacet; label: string; value: string[]; set: (v: string[]) => void }[] = [
    { key: 'category', label: 'Category', value: category, set: setCategory },
    { key: 'status', label: 'Current result', value: status, set: setStatus },
    { key: 'severity', label: 'Severity', value: severity, set: setSeverity },
    { key: 'confidence', label: 'Evidence confidence', value: confidence, set: setConfidence },
    { key: 'review', label: 'Human review', value: review, set: setReview },
    { key: 'host', label: 'Machine', value: host, set: setHost },
    { key: 'asset_type', label: 'Asset type', value: assetType, set: setAssetType },
    { key: 'source', label: 'Source', value: source, set: setSource },
    { key: 'benchmark', label: 'Benchmark', value: benchmark, set: setBenchmark },
    { key: 'benchmark_release', label: 'Release', value: release, set: setRelease },
  ];
  const optionLabel = (key: FindingFacet, value: string, fallback: string) => {
    const labels: Record<string, string> = key === 'confidence' ? CONFIDENCE_LABELS : key === 'review' ? REVIEW_FILTER_LABELS : LABELS;
    return ['category', 'severity', 'status', 'confidence', 'review'].includes(key) || value === '__missing__' ? labels[value] ?? fallback : fallback;
  };
  const options = (key: FindingFacet, selected: string[]) => {
    const result = (data?.facets?.[key] ?? []).map((o) => ({
      value: selected.find((s) => s.trim().toLowerCase() === o.value) ?? o.value,
      label: `${optionLabel(key, o.value, o.label)} (${o.count})`,
    }));
    for (const value of selected) {
      if (!result.some((o) => o.value === value)) result.push({ value, label: `${optionLabel(key, value, value)} (0)` });
    }
    return result;
  };
  const quickView = (view: 'stig' | 'cve' | 'open' | 'all') => {
    axes.forEach((a) => a.set([]));
    setQ('');
    setStatus(view === 'all' ? [] : ['open']);
    setCategory(view === 'stig' || view === 'cve' ? [view] : []);
    setPage(1);
  };
  const reset = () => { quickView('open'); setSortBy('default'); setSortDir('asc'); };
  const activeQuickView = !q && !severity.length && !source.length && !assetType.length && !host.length && !benchmark.length && !release.length && !confidence.length && !review.length
    ? (!status.length && !category.length ? 'all' : status.length === 1 && status[0] === 'open'
      ? (!category.length ? 'open' : category.length === 1 ? category[0] : '') : '') : '';
  const explainAll = async () => {
    setExplaining(true);
    try {
      const r = await api.explainAll();
      notifications.show({ message: `${r.queued} explanations queued on the local model` });
    } catch (e) {
      notifications.show({ color: 'red', title: 'Refused', message: errorText(e) });
    } finally { setExplaining(false); }
  };

  return (
    <Stack gap="md">
      <PageTitle title="Findings" subtitle="Filter STIG checks, vulnerabilities and hunt results across the current findings view."
        right={<>
          <Tooltip label="Queues explanations for all open findings, regardless of these filters">
            <Button variant="light" leftSection={<IconSparkles size={16} />} loading={explaining} onClick={() => void explainAll()}>Explain all open</Button>
          </Tooltip>
          <Button variant="light" onClick={() => void reload()} loading={loading}>Refresh</Button>
        </>} />
      <Paper withBorder radius="md" p="md">
        <Stack gap="md">
          <Group justify="space-between">
            <Group gap="xs" aria-label="Quick views">
              {([{ value: 'stig', label: 'Open STIGs' }, { value: 'cve', label: 'Open CVEs' }, { value: 'open', label: 'All open' }, { value: 'all', label: 'All results' }] as const).map((v) => (
                <Button key={v.value} size="xs" variant={activeQuickView === v.value ? 'filled' : 'light'} aria-pressed={activeQuickView === v.value} onClick={() => quickView(v.value)}>{v.label}</Button>
              ))}
            </Group>
            <Group gap="xs">
              <Button size="xs" variant="subtle" onClick={() => quickView('all')}>Clear filters</Button>
              <Button size="xs" variant="subtle" onClick={reset}>Reset defaults</Button>
            </Group>
          </Group>
          <TextInput label="Search findings" placeholder="CVE or STIG identifier, rule, title, machine…" leftSection={<IconSearch size={16} />} value={q}
            onChange={(e) => { setPage(1); setQ(e.currentTarget.value); }}
            rightSection={q ? <ActionIcon variant="subtle" aria-label="Clear search" onClick={() => { setQ(''); setPage(1); }}><IconX size={16} /></ActionIcon> : undefined} />
          <SimpleGrid cols={{ base: 1, sm: 2, md: 4 }} spacing="sm">
            {axes.map((a) => <MultiSelect key={a.key} label={a.label} data={options(a.key, a.value)} value={a.value}
              disabled={(a.key === 'confidence' && !confidenceAvailable) || (a.key === 'review' && !reviewAvailable)}
              onChange={(value) => { setPage(1); a.set(value); }} searchable clearable placeholder={a.value.length ? undefined : 'All'} nothingFoundMessage="No matching options" />)}
          </SimpleGrid>
          {data && (!confidenceAvailable || !reviewAvailable) && <Text size="sm" c="dimmed">This server has not reported all confidence and review features. Missing values appear as Unknown or Unreviewed. Unavailable filters and sorts are paused until the server is upgraded; saved preferences are retained.</Text>}
          <Group justify="space-between" align="flex-end">
            <Text size="xs" c="dimmed" maw={620}>Option counts cover the full view. Categories can overlap. Current result includes verified fixes. Original scanner observations, evidence confidence and human review are shown separately.</Text>
            <Group gap="sm">
              <Select label="Sort by" data={SORTS.map((s) => ({ ...s, disabled: (s.value === 'confidence' && !confidenceAvailable) || (s.value === 'review' && !reviewAvailable) }))} value={sortBy} allowDeselect={false} w={190}
                onChange={(v) => { setSortBy((v ?? 'default') as FindingSort); if (v === 'default') setSortDir('asc'); setPage(1); }} />
              <Select label="Direction" data={[{ value: 'asc', label: 'Ascending' }, { value: 'desc', label: 'Descending' }]} value={sortDir}
                disabled={sortBy === 'default'} allowDeselect={false} w={150} onChange={(v) => { setSortDir((v ?? 'asc') as SortDirection); setPage(1); }} />
            </Group>
          </Group>
        </Stack>
      </Paper>
      <Group justify="space-between" aria-live="polite">
        <Text size="sm" fw={600}>{loading ? 'Updating results…' : data ? `${data.total.toLocaleString()} matching / ${data.unfiltered_total.toLocaleString()} total results` : 'Results unavailable'}</Text>
        {data && <Text size="xs" c="dimmed">Current view · baseline {data.scan_id ?? 'none'}</Text>}
      </Group>
      <Text size="xs" c="dimmed">Open a row for finding details. Keyboard: focus a row and press Enter or Space. Confidence and review buttons open their own controls.</Text>
      <AsyncView state={st} what="Loading findings" isEmpty={(d) => d.findings.length === 0}
        empty={<Empty title="No findings match"><Stack align="center" gap="xs"><Text size="sm">Choose another quick view, clear filters, or run a scan.</Text><Button variant="light" onClick={() => quickView('all')}>Show all results</Button></Stack></Empty>}>
        {(d) => <Paper withBorder radius="md">
          <ScrollArea>
            <Table striped highlightOnHover verticalSpacing="sm" miw={1550}>
              <Table.Thead><Table.Tr>
                <Table.Th>Severity</Table.Th><Table.Th>Scanner result</Table.Th><Table.Th>Evidence confidence</Table.Th><Table.Th>Human review</Table.Th><Table.Th>Machine / type</Table.Th><Table.Th>Category / source</Table.Th>
                <Table.Th>Rule / title</Table.Th><Table.Th>Benchmark / release</Table.Th><Table.Th>Observed</Table.Th><Table.Th>Fix / explanation / proposal</Table.Th>
              </Table.Tr></Table.Thead>
              <Table.Tbody>{d.findings.map((f) => <Table.Tr key={f.id} className="finding-row" tabIndex={0}
                aria-label={`Open finding ${f.rule_version || f.rule_id}: ${f.title} on ${f.host || 'unknown machine'}`} aria-haspopup="dialog"
                {...findingRowHandlers(() => { setReviewOpen(false); setDrawer(f.id); })}>
                <Table.Td><SeverityBadge severity={f.severity} size="sm" /></Table.Td>
                <Table.Td><Badge color={statusColor(f.scanner_status ?? f.remediated?.scan_status ?? f.status)} variant="light" radius="sm">{LABELS[f.scanner_status ?? f.remediated?.scan_status ?? f.status]}</Badge>
                  {(f.needs_rescan || (f.scanner_status ?? f.remediated?.scan_status ?? f.status) !== f.status) && <Text size="xs" c={f.needs_rescan ? 'orange' : 'dimmed'} mt={4}>{findingResultLabel(f)}: {LABELS[f.status]}</Text>}</Table.Td>
                <Table.Td miw={160} maw={240}><ConfidenceBadge confidence={f.confidence} /><Text size="xs" c="dimmed" lineClamp={2} mt={4}>{f.confidence?.reason || 'Evidence strength not reported'}</Text></Table.Td>
                <Table.Td miw={180} maw={240}><ReviewBadge review={f.review} onClick={() => { setReviewOpen(true); setDrawer(f.id); }} />
                  {f.review?.reopened_reason && <Text size="xs" c="orange" lineClamp={2} mt={4}>Reopened: {f.review.reopened_reason}</Text>}</Table.Td>
                <Table.Td><Group gap={4} wrap="nowrap"><AssetIcon type={f.asset_type} size={14} /><Text size="sm">{f.host || 'Not recorded'}</Text></Group><Text size="xs" c="dimmed">{f.asset_type || 'Not recorded'}</Text></Table.Td>
                <Table.Td><Group gap={4}>{f.categories.map((c) => <Badge key={c} size="xs" variant="light" color={c === 'stig' ? 'blue' : c === 'cve' ? 'orange' : 'gray'}>{LABELS[c]}</Badge>)}</Group><Text size="xs" c="dimmed" mt={4}>{f.source || 'Not recorded'}</Text></Table.Td>
                <Table.Td miw={280} maw={420}><Button variant="subtle" size="compact-xs" onClick={() => { setReviewOpen(false); setDrawer(f.id); }} aria-label={`Open finding ${f.rule_version || f.rule_id}`}><Mono>{f.rule_version || f.rule_id}</Mono></Button><Text size="sm" lineClamp={2} mt={4}>{f.title}</Text>
                  <Text size="xs" c="dimmed" lineClamp={2}>{Array.from(new Set([f.group_id, ...f.references.filter((r) => r.system === 'cve').map((r) => r.id)])).filter(Boolean).join(' · ')}</Text></Table.Td>
                <Table.Td maw={240}><Text size="xs" lineClamp={2}>{f.benchmark || 'Not recorded'}</Text><Text size="xs" c="dimmed">{f.benchmark_release || 'Not recorded'}</Text></Table.Td>
                <Table.Td><Text size="xs">{f.reassessment ? fmtZonedTime(f.reassessment.observation.observed_at)
                  : f.collected_at && !Number.isNaN(Date.parse(f.collected_at)) ? fmtTime(f.collected_at) : 'Not recorded'}</Text>
                  <FindingReassessment reassessment={f.reassessment} compact /></Table.Td>
                <Table.Td><Group gap="sm"><Yes v={!!f.fix} tip={f.fix?.fix_ref ?? 'No library fix'} /><Yes v={!!f.explanation} tip={f.explanation ? 'Explanation ready' : 'Not yet explained'} />{f.proposal ? <StateBadge state={f.proposal.state} /> : <Text size="xs" c="dimmed">No proposal</Text>}</Group>
                  <Button variant="light" size="compact-xs" mt="xs" onClick={() => { setReviewOpen(false); setDrawer(f.id); }} aria-label={`View details for ${f.title}`}>View details</Button></Table.Td>
              </Table.Tr>)}</Table.Tbody>
            </Table>
          </ScrollArea>
          <Group justify="space-between" p="sm"><Text size="xs" c="dimmed">Showing {d.offset + 1}–{d.offset + d.findings.length} of {d.total.toLocaleString()} matching results</Text>
            {d.total > PAGE && <Pagination total={Math.ceil(d.total / PAGE)} value={page} onChange={setPage} />}</Group>
        </Paper>}
      </AsyncView>
      <FindingDrawer findingId={drawer} onClose={() => setDrawer(null)} onProposed={() => void reload()} onReviewed={() => void reload()} initialReviewOpen={reviewOpen} />
    </Stack>
  );
}
