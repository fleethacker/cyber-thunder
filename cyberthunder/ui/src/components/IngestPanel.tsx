// Bulletin ingestion; STIG uploads and delta rescans live in the STIG Library.
import { Button, FileButton, Group, Paper, SimpleGrid, Stack, Table, Text } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { IconFileUpload } from '@tabler/icons-react';
import { useState, type DragEvent, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { api, errorText } from '../api/client';
import type { BulletinResult } from '../api/types';
import { ErrorBox, Mono, SeverityBadge } from './common';

function DropZone({ label, accept, busy, onFile, children }: { label: string; accept: string; busy: boolean; onFile: (f: File) => void; children?: ReactNode }) {
  const [over, setOver] = useState(false);
  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    setOver(false);
    const f = e.dataTransfer.files?.[0];
    if (f) onFile(f);
  };
  return (
    <Paper
      withBorder
      p="lg"
      radius="md"
      onDragOver={(e) => { e.preventDefault(); setOver(true); }}
      onDragLeave={() => setOver(false)}
      onDrop={onDrop}
      style={{ borderStyle: 'dashed', borderWidth: 2, borderColor: over ? 'var(--mantine-color-blue-5)' : undefined }}
    >
      <Stack align="center" gap="xs">
        <IconFileUpload size={28} opacity={0.6} />
        <Text fw={600}>{label}</Text>
        {children}
        <FileButton onChange={(f) => f && onFile(f)} accept={accept}>
          {(props) => <Button {...props} variant="light" loading={busy}>Choose file</Button>}
        </FileButton>
      </Stack>
    </Paper>
  );
}

function BulletinSummary({ b }: { b: BulletinResult }) {
  return (
    <Paper withBorder p="md" radius="md">
      <Stack gap="xs">
        <Group gap="xs"><Text fw={700}>Bulletin</Text><Mono>{b.bulletin_id}</Mono></Group>
        <Text size="sm">{b.hosts_affected.length ? `Affected hosts: ${b.hosts_affected.join(', ')}` : 'No host in the latest package inventory is affected.'}</Text>
        {b.findings.length > 0 && (
          <Table withTableBorder striped>
            <Table.Tbody>
              {b.findings.map((f) => (
                <Table.Tr key={f.id}>
                  <Table.Td w={90}><SeverityBadge severity={f.severity} size="xs" /></Table.Td>
                  <Table.Td w={140}><Text size="sm">{f.host}</Text></Table.Td>
                  <Table.Td><Text size="sm">{f.title}</Text></Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
      </Stack>
    </Paper>
  );
}

export function IngestPanel() {
  const [bulletin, setBulletin] = useState<BulletinResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const upload = async (f: File) => {
    setBusy(true);
    setError(null);
    try {
      const b = await api.ingestBulletin(f);
      setBulletin(b);
      notifications.show({ message: `${b.findings.length} new findings on ${b.hosts_affected.length} hosts` });
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Stack gap="sm">
      <Text fw={700} size="lg">Ingest</Text>
      <SimpleGrid cols={{ base: 1, md: 2 }}>
        <Paper withBorder p="lg" radius="md"><Stack align="center" gap="sm">
          <Text fw={600}>STIG releases</Text>
          <Text size="sm" c="dimmed" ta="center">Upload, inspect versions, and rescan changed rules from the STIG Library.</Text>
          <Button component={Link} to="/content?tab=transfers" variant="light">Open STIG imports</Button>
        </Stack></Paper>
        <DropZone label="Drop a vulnerability bulletin (IAVM JSON)" accept=".json,application/json" busy={busy} onFile={(f) => void upload(f)} />
      </SimpleGrid>
      {error && <ErrorBox error={error} />}
      {bulletin && <BulletinSummary b={bulletin} />}
    </Stack>
  );
}
