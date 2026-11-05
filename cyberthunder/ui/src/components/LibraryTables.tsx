import { Badge, Button, Group, Pagination, Paper, Stack, Table, Text, TextInput } from '@mantine/core';
import { IconSearch } from '@tabler/icons-react';
import { useState, type ReactNode } from 'react';
import type { ContentRow, HeldFile, LibraryCatalog } from '../api/types';
import { fmtBytes, fmtZonedTime } from '../lib/format';

export const KIND_LABELS: Record<string, string> = {
  manual_stig: 'Manual STIG', srg: 'SRG', scap_benchmark: 'SCAP benchmark',
};
export const kindLabel = (kind: string) => KIND_LABELS[kind] ?? kind.replace(/_/g, ' ');
const PAGE_SIZE = 12;

export function LibraryTable<T>({ rows, searchText, label, headings, render, empty, toolbar }: {
  rows: T[];
  searchText: (row: T) => string;
  label: string;
  headings: ReactNode;
  render: (row: T, index: number) => ReactNode;
  empty: string;
  toolbar?: (displayed: T[]) => ReactNode;
}) {
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(1);
  const needle = query.trim().toLowerCase();
  const filtered = rows.filter((row) => searchText(row).toLowerCase().includes(needle));
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const current = Math.min(page, pages);
  const start = (current - 1) * PAGE_SIZE;
  const displayed = filtered.slice(start, start + PAGE_SIZE);
  return (
    <Stack gap="sm">
      <TextInput label={`Search ${label}`} placeholder={`Search ${label}`} leftSection={<IconSearch size={16} />}
        value={query} onChange={(event) => { setQuery(event.currentTarget.value); setPage(1); }} />
      {toolbar?.(displayed)}
      {filtered.length ? (
        <Table.ScrollContainer minWidth={660}>
          <Table striped highlightOnHover withTableBorder verticalSpacing="sm" fz="sm">
            <Table.Thead><Table.Tr>{headings}</Table.Tr></Table.Thead>
            <Table.Tbody>{displayed.map((row, index) => render(row, start + index))}</Table.Tbody>
          </Table>
        </Table.ScrollContainer>
      ) : <Paper withBorder p="lg" radius="md"><Text size="sm" c="dimmed">{needle ? 'No results match your search.' : empty}</Text></Paper>}
      <Group justify="space-between">
        <Text size="xs" c="dimmed">{filtered.length ? `${start + 1}–${Math.min(start + PAGE_SIZE, filtered.length)} of ${filtered.length}` : '0'} {label}{needle ? ` (${rows.length} total)` : ''} · {PAGE_SIZE} per page</Text>
        {pages > 1 && <Pagination size="sm" total={pages} value={current} onChange={setPage} aria-label={`${label} pages`} />}
      </Group>
    </Stack>
  );
}

export function HeldTable({ files }: { files: HeldFile[] }) {
  return <LibraryTable rows={files} label="local files" empty="No content on this node. Upload files or download updates in Transfers / import."
    searchText={(f) => `${f.product_key} ${f.benchmark_id} ${f.filename} ${f.ingest?.upload?.filename} ${f.version_label} ${f.benchmark_release} ${kindLabel(f.kind)} ${f.source}`}
    headings={<><Table.Th>File / product</Table.Th><Table.Th>Type / version</Table.Th><Table.Th>Publisher date</Table.Th><Table.Th>Local provenance</Table.Th></>}
    render={(f) => <Table.Tr key={f.filename}>
      <Table.Td><Text size="sm" fw={600} style={{ overflowWrap: 'anywhere' }}>{f.product_key ?? f.benchmark_id ?? 'Unmapped product'}</Text>
        {f.product_key && f.benchmark_id && <Text size="xs" c="dimmed" style={{ overflowWrap: 'anywhere' }}>{f.benchmark_id}</Text>}
        <Text size="xs" style={{ overflowWrap: 'anywhere' }}>{f.ingest?.upload?.filename ?? f.filename}</Text><Text size="xs" c="dimmed">{fmtBytes(f.bytes)}</Text></Table.Td>
      <Table.Td><Text size="sm">{kindLabel(f.kind)}</Text><Text size="sm" fw={600}>{f.version_label ?? f.benchmark_release ?? 'Version not provided'}</Text>
        {f.version_label && f.benchmark_release && <Text size="xs" c="dimmed">{f.benchmark_release}</Text>}
        {f.ingest?.datastream_path && <Badge size="xs" variant="light">SCAP datastream indexed</Badge>}</Table.Td>
      <Table.Td>{fmtZonedTime(f.upload_date, 'Not provided')}</Table.Td>
      <Table.Td><FileProvenance file={f} /></Table.Td>
    </Table.Tr>} />;
}

export function FileProvenance({ file }: { file: HeldFile }) {
  const upload = file.ingest?.upload;
  const at = upload?.imported_at ?? file.fetched_at;
  const by = upload?.imported_by ?? file.fetched_by;
  return <Stack gap={2}>
    <Text size="sm" fw={600}>{file.source === 'pulled' ? 'Downloaded' : file.source === 'bundled' ? 'Bundled reference' : file.source === 'uploaded' ? 'Uploaded locally' : 'Folder import'}</Text>
    <Text size="xs">{fmtZonedTime(at)}</Text>
    {by && <Text size="xs" c="dimmed">{by}</Text>}
    {upload?.authenticity_verified === false && <Text size="xs" c="orange">Publisher authenticity not verified</Text>}
  </Stack>;
}

export function CatalogTable({ catalogs }: { catalogs: LibraryCatalog[] }) {
  return <LibraryTable rows={catalogs} label="rule catalogs" empty="No rule catalogs have been indexed."
    searchText={(c) => `${c.title} ${c.benchmark_id} ${c.filename} ${c.release}`}
    headings={<><Table.Th>Catalog</Table.Th><Table.Th>Release / rules</Table.Th><Table.Th>Origin</Table.Th><Table.Th>Imported locally</Table.Th></>}
    render={(c) => <Table.Tr key={c.path}>
      <Table.Td><Text size="sm" fw={600}>{c.title || c.benchmark_id}</Text><Text size="xs" c="dimmed" style={{ overflowWrap: 'anywhere' }}>{c.filename}</Text></Table.Td>
      <Table.Td>{c.release || 'Not provided'}<Text size="xs" c="dimmed">{c.rules.toLocaleString()} rules</Text></Table.Td>
      <Table.Td><Badge variant="light" color={c.origin === 'bundled_reference' ? 'gray' : 'blue'}>{c.origin === 'bundled_reference' ? 'Bundled reference' : 'Imported catalog'}</Badge></Table.Td>
      <Table.Td>{c.origin === 'bundled_reference' ? 'Included with this build' : fmtZonedTime(c.imported_at)}</Table.Td>
    </Table.Tr>} />;
}

export function AvailableTable({ rows }: { rows: ContentRow[] }) {
  return <LibraryTable rows={rows} label="available releases" empty="No releases are listed for this product."
    searchText={(r) => `${r.filename} ${r.version_label} ${kindLabel(r.kind)}`}
    headings={<><Table.Th>Release</Table.Th><Table.Th>Type / version</Table.Th><Table.Th>Publisher date</Table.Th><Table.Th>Availability</Table.Th></>}
    render={(r) => <Table.Tr key={r.filename}>
      <Table.Td><Text size="xs" style={{ overflowWrap: 'anywhere' }}>{r.filename}</Text></Table.Td>
      <Table.Td>{kindLabel(r.kind)}<Text size="sm" fw={600}>{r.version_label ?? 'Not provided'}</Text></Table.Td>
      <Table.Td>{fmtZonedTime(r.upload_date, 'Not provided')}</Table.Td>
      <Table.Td>{r.sunset ? <Badge color="orange">Retired</Badge> : r.allowed === false ? <Badge color="gray">External only</Badge> : <Badge variant="light">Listed</Badge>}</Table.Td>
    </Table.Tr>} />;
}

export function DisplayedSelection<T>({ displayed, selected, keyOf, onChange, disabled }: {
  displayed: T[]; selected: string[]; keyOf: (row: T) => string; onChange: (keys: string[]) => void; disabled?: boolean;
}) {
  const keys = displayed.map(keyOf);
  return <Group gap="xs">
    <Button size="compact-sm" variant="subtle" disabled={disabled || !keys.length}
      onClick={() => onChange([...new Set([...selected, ...keys])])}>Select displayed</Button>
    <Button size="compact-sm" variant="subtle" disabled={disabled || !keys.length}
      onClick={() => onChange(selected.filter((key) => !keys.includes(key)))}>Clear displayed</Button>
  </Group>;
}
