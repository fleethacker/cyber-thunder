import { Button, Popover, Stack, Text } from '@mantine/core';
import type { FindingReassessment as Reassessment } from '../api/types';
import { fmtZonedTime } from '../lib/format';

export function FindingReassessment({ reassessment, compact = false }: {
  reassessment?: Reassessment | null; compact?: boolean;
}) {
  const gap = reassessment?.status === 'not_reassessed';
  if (compact && !gap) return null;
  const details = <Stack gap={4}>
    <Text size="sm" fw={600} c={gap ? 'orange' : undefined}>{gap ? 'Not reassessed' : 'Reassessment history'}</Text>
    <Text size="sm">{reassessment?.explanation || 'This server has not reported reassessment history.'}</Text>
    {reassessment && <Text size="xs" c="dimmed">
      Observation: {reassessment.observation.observed_at ? fmtZonedTime(reassessment.observation.observed_at) : 'Time not recorded'}
      {' · '}{reassessment.observation.source || 'Source not recorded'}
      {reassessment.observation.scan_id && ` · scan ${reassessment.observation.scan_id}`}
    </Text>}
    {reassessment?.latest_attempt && <Text size="xs" c="dimmed">
      Later scan: {reassessment.latest_attempt.scan_id} · started {fmtZonedTime(reassessment.latest_attempt.started_at)}
      {reassessment.latest_attempt.target_status && ` · target ${reassessment.latest_attempt.target_status.replace(/_/g, ' ')}`}
    </Text>}
    {gap && <Text size="xs">The earlier scanner result remains. This does not mean fixed or false positive, and does not change evidence confidence, human review or approvals.</Text>}
  </Stack>;
  if (!compact) return details;
  return <Popover width={380} position="bottom-start" withArrow trapFocus>
    <Popover.Target>
      <Button variant="light" color="orange" size="compact-xs" mt={4}
        aria-label="Not reassessed: show later scan and original observation">Not reassessed</Button>
    </Popover.Target>
    <Popover.Dropdown style={{ maxWidth: 'calc(100vw - 40px)' }}>{details}</Popover.Dropdown>
  </Popover>;
}
