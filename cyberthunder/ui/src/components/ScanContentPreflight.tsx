import { Accordion, Alert, Button, Group, Loader, Stack, Text } from '@mantine/core';
import { useEffect, useState } from 'react';
import { errorText } from '../api/client';
import { scanPreflight, type ScanPreflight } from '../api/scanContent';
import { ScanCoverage } from './ScanCoverage';

export function ScanContentPreflight({ targetIds, modules, refreshKey = '' }: { targetIds: string[]; modules: string[]; refreshKey?: string }) {
  const [revision, setRevision] = useState(0);
  const [view, setView] = useState<{ key: string; data?: ScanPreflight; error?: string }>();
  const key = JSON.stringify([targetIds, modules, refreshKey, revision]);
  useEffect(() => {
    let active = true;
    if (modules.length) void scanPreflight(targetIds, modules).then(
      (data) => { if (active) setView({ key, data }); },
      (error) => { if (active) setView({ key, error: errorText(error) }); },
    );
    return () => { active = false; };
  }, [key]);
  const current = view?.key === key ? view : undefined;
  return <Stack gap="xs">
    <Group justify="space-between"><Text fw={600}>Scan coverage preflight</Text>
      <Button size="xs" variant="subtle" disabled={!modules.length} onClick={() => setRevision((n) => n + 1)}>Refresh local coverage</Button></Group>
    <Text size="sm" c="dimmed">This view reads local records only. Starting a scan does not download STIGs or install scanners. Download or import content explicitly in the STIG Library; maintained products control automatic updates.</Text>
    {!modules.length ? <Text size="sm">Choose a scan module to see coverage.</Text>
      : !current ? <Group><Loader size="xs" /><Text size="sm">Reading local coverage…</Text></Group>
      : current.error ? <Alert color="yellow" title="Coverage unknown">Could not read preflight: {current.error}</Alert>
      : <Accordion variant="contained">{current.data?.targets.map((coverage) => <Accordion.Item value={coverage.target_id} key={coverage.target_id}>
        <Accordion.Control>{coverage.target_id} — {coverage.products.length ? coverage.products.map((p) => p.product_key).join(', ') : 'Product applicability unknown'}</Accordion.Control>
        <Accordion.Panel><ScanCoverage coverage={coverage} /></Accordion.Panel>
      </Accordion.Item>)}</Accordion>}
    {current?.data?.targets.length === 0 && <Text size="sm">No in-scope targets selected.</Text>}
  </Stack>;
}
