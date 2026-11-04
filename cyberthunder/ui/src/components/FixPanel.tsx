// Blast-radius tags for a library fix: disruption, reboot, service restarts, patch, reversible.
import { Badge, Group } from '@mantine/core';
import type { FixEntry } from '../api/types';

export function RiskTagsForFix({ fix }: { fix: FixEntry }) {
  const dColor = { low: 'green', medium: 'orange', high: 'red' }[fix.disruption] ?? 'gray';
  return (
    <Group gap={6}>
      <Badge color={dColor} variant="light">disruption: {fix.disruption}</Badge>
      <Badge color={fix.reboot ? 'red' : 'gray'} variant={fix.reboot ? 'filled' : 'outline'}>{fix.reboot ? 'reboot required' : 'no reboot'}</Badge>
      {fix.restarts_services.length > 0
        ? <Badge color="orange" variant="light" tt="none">restarts {fix.restarts_services.join(', ')}</Badge>
        : <Badge color="gray" variant="outline">no service restart</Badge>}
      {fix.patch && <Badge color="orange" variant="filled">patch / package change</Badge>}
      <Badge color={fix.reversible ? 'teal' : 'red'} variant={fix.reversible ? 'light' : 'filled'}>{fix.reversible ? 'reversible' : 'NOT reversible'}</Badge>
    </Group>
  );
}
