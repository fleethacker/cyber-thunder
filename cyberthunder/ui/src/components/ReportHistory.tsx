import { Badge, Button, Group, Pagination, Paper, ScrollArea, Select, Stack, Table, Text, TextInput } from '@mantine/core';
import { useDebouncedValue } from '@mantine/hooks';
import { IconDownload, IconSearch } from '@tabler/icons-react';
import { useEffect, useState } from 'react';
import { api, errorText, url } from '../api/client';
import type { ReportHistory as HistoryPage, SavedReportContent } from '../api/types';
import { fmtBytes, fmtTime } from '../lib/format';
import { useAuditListener } from '../state/AppState';
import { ErrorBox, Loading, Mono } from './common';

const PAGE_SIZE = 20;
const TYPES = [
  { value: 'commander', label: 'Commander one-pager' }, { value: 'poam', label: 'POA&M' },
  { value: 'checklist', label: 'Updated checklist' }, { value: 'target', label: 'Target report' },
];

export function ReportHistory() {
  const [search, setSearch] = useState('');
  const [query] = useDebouncedValue(search, 300);
  const [kind, setKind] = useState<string | null>(null);
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [page, setPage] = useState(1);
  const [revision, setRevision] = useState(0);
  const [data, setData] = useState<HistoryPage>();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [report, setReport] = useState<SavedReportContent>();
  const [reportError, setReportError] = useState<string | null>(null);
  const invalidDates = !!from && !!to && from > to;

  useAuditListener((event) => {
    if (event.action === 'report.render') setRevision((value) => value + 1);
  });
  useEffect(() => { setPage(1); }, [query, kind, from, to]);
  useEffect(() => {
    let alive = true;
    if (invalidDates) { setLoading(false); return; }
    setLoading(true);
    setError(null);
    api.reportHistory({ q: query || undefined, kind: kind || undefined, from_date: from || undefined,
      to_date: to || undefined, offset: (page - 1) * PAGE_SIZE, limit: PAGE_SIZE })
      .then((result) => { if (alive) setData(result); })
      .catch((failure) => { if (alive) setError(errorText(failure)); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [query, kind, from, to, page, revision, invalidDates]);

  useEffect(() => {
    let alive = true;
    setReport(undefined);
    setReportError(null);
    if (selected) {
      api.savedReport(selected)
        .then((result) => { if (alive) setReport(result); })
        .catch((failure) => { if (alive) setReportError(errorText(failure)); });
    }
    return () => { alive = false; };
  }, [selected]);

  return (
    <Paper withBorder radius="md" p="md">
      <Stack gap="sm">
        <Group justify="space-between">
          <div><Text fw={700}>Report history</Text><Text size="sm" c="dimmed">Search saved report contents, assets, scan IDs and operators.</Text></div>
          <Button variant="subtle" size="sm" loading={loading} onClick={() => setRevision((value) => value + 1)}>Refresh history</Button>
        </Group>
        <Group align="flex-end">
          <TextInput label="Search reports" placeholder="Keyword, asset, scan ID or operator" value={search}
            onChange={(event) => setSearch(event.currentTarget.value)} leftSection={<IconSearch size={16} />}
            maxLength={200} style={{ flex: 1, minWidth: 220 }} />
          <Select label="Report type" placeholder="All types" data={TYPES} value={kind} onChange={setKind} clearable w={210} />
          <TextInput type="date" label="From date (UTC)" value={from} onChange={(event) => setFrom(event.currentTarget.value)} />
          <TextInput type="date" label="To date (UTC)" value={to} onChange={(event) => setTo(event.currentTarget.value)} />
          {(search || kind || from || to) && <Button variant="default" onClick={() => { setSearch(''); setKind(null); setFrom(''); setTo(''); setPage(1); }}>Clear filters</Button>}
        </Group>
        {invalidDates && <Text c="red" size="sm">From date must be on or before To date.</Text>}
        {error && <ErrorBox error={error} />}
        {loading && <Loading what="Searching report history" />}
        {!loading && !error && !invalidDates && data && (
          <>
            <Text size="sm" c="dimmed">{data.total} saved report{data.total === 1 ? '' : 's'}{query || kind || from || to ? ' matching these filters' : ''}</Text>
            {data.reports.length === 0 ? <Text size="sm">{query || kind || from || to ? 'No saved reports match these filters.' : 'No saved reports yet. Generate a report below or write a target report in Mission.'}</Text> : (
              <ScrollArea>
                <Table withTableBorder striped miw={800}>
                  <Table.Thead><Table.Tr><Table.Th>Report</Table.Th><Table.Th>Assets</Table.Th><Table.Th>Generated</Table.Th><Table.Th>Operator</Table.Th><Table.Th>Actions</Table.Th></Table.Tr></Table.Thead>
                  <Table.Tbody>
                    {data.reports.map((item) => (
                      <Table.Tr key={item.id} bg={selected === item.id ? 'var(--mantine-color-default-hover)' : undefined}>
                        <Table.Td><Text size="sm" fw={600}>{item.title}</Text><Badge size="xs" variant="light">{item.format.toUpperCase()}</Badge><Text size="xs" c="dimmed">{fmtBytes(item.bytes)}</Text></Table.Td>
                        <Table.Td><Text size="sm">{item.target_names.join(', ') || 'All assets'}</Text>{item.scan_id && <Text size="xs" c="dimmed"><Mono>{item.scan_id}</Mono></Text>}</Table.Td>
                        <Table.Td><Text size="sm">{fmtTime(item.generated_at)}</Text></Table.Td>
                        <Table.Td><Text size="sm">{item.generated_by}</Text></Table.Td>
                        <Table.Td><Group gap="xs" wrap="nowrap"><Button size="xs" variant="light" onClick={() => setSelected(item.id)}>Open</Button><Button component="a" size="xs" variant="subtle" href={url(`/reports/history/${encodeURIComponent(item.id)}/download`)} download={item.filename} leftSection={<IconDownload size={14} />}>Download</Button></Group></Table.Td>
                      </Table.Tr>
                    ))}
                  </Table.Tbody>
                </Table>
              </ScrollArea>
            )}
            {data.total > PAGE_SIZE && <Pagination value={page} onChange={setPage} total={Math.ceil(data.total / PAGE_SIZE)} aria-label="Report history pages" />}
          </>
        )}
        {selected && (
          <Stack gap="sm" mt="sm">
            <Group justify="space-between"><Text fw={700}>Saved report</Text><Button size="xs" variant="subtle" onClick={() => setSelected(null)}>Close saved report</Button></Group>
            {reportError ? <ErrorBox error={reportError} /> : !report ? <Loading what="Opening saved report" /> : (
              <>
                <Text size="sm">{report.title} · {fmtTime(report.generated_at)} · {report.generated_by}</Text>
                {report.format === 'html'
                  ? <iframe title="Saved report preview" srcDoc={report.content} sandbox="" style={{ width: '100%', height: 640, border: '1px solid var(--mantine-color-default-border)', borderRadius: 8, background: 'white' }} />
                  : <ScrollArea h={440}><pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontSize: 12 }}>{report.content}</pre></ScrollArea>}
              </>
            )}
          </Stack>
        )}
      </Stack>
    </Paper>
  );
}
