import { Anchor, Badge, Group, Stack, Text } from '@mantine/core';
import { Link } from 'react-router-dom';
import type { ScanCoverage as Coverage } from '../api/scanContent';
import { fmtAgo, fmtTime } from '../lib/format';

const label = (value: string) => value.replace(/_/g, ' ');

export function ScanCoverage({ coverage }: { coverage?: Coverage | null }) {
  if (!coverage) return <Text size="sm" c="dimmed">Coverage unknown — this run has no coverage record.</Text>;
  return <Stack gap="xs">
    <Group gap="xs">
      <Badge color="yellow">{coverage.phase === 'preflight' ? 'Local preflight' : 'Observed coverage'}</Badge>
      {!coverage.complete && <Badge color="yellow" variant="outline">Incomplete or unverified</Badge>}
      {coverage.simulated && <Badge color="gray">Simulated</Badge>}
    </Group>
    <Text size="sm">Native checks: {label(coverage.native.status)} · Product applicability: {label(coverage.applicability.status)}</Text>
    {coverage.applicability.observed_at && <Text size="xs" c="dimmed">OS facts last collected {fmtAgo(coverage.applicability.observed_at)} ({fmtTime(coverage.applicability.observed_at)})</Text>}
    <Text size="sm">SCAP engine: {coverage.scanner.engine ?? 'Not configured for this asset type'}{coverage.scanner.location ? ` on ${coverage.scanner.location}` : ''} · {label(coverage.scanner.status)}</Text>
    <Text size="sm">Scanner content: {label(coverage.scanner.content_status)} · Benchmark applicability: {label(coverage.scanner.applicability)}</Text>
    <Text size="xs" c="dimmed">{coverage.scanner.observed_at
      ? `Capability last observed ${fmtAgo(coverage.scanner.observed_at)} (${fmtTime(coverage.scanner.observed_at)})${coverage.scanner.stale ? ' — stale or configuration changed' : '; this is not a current probe'}`
      : 'No scanner capability observation recorded.'}</Text>
    {coverage.products.map((product) => <Text size="sm" key={product.product_key}>
      <Anchor component={Link} to={product.library_url}>{product.product_key}</Anchor>
      {` · Manual guide: ${label(product.manual.status)} · SCAP download: ${label(product.scap.status)}`}
    </Text>)}
    {coverage.warnings.length > 0 && <ul style={{ margin: 0, paddingLeft: 20 }}>{coverage.warnings.map((warning) => <li key={warning}><Text size="xs">{warning}</Text></li>)}</ul>}
    <Group gap="md">{coverage.actions.map((action) => <Anchor component={Link} to={action.href} size="sm" key={action.href}>{action.label}</Anchor>)}</Group>
  </Stack>;
}
