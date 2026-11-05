import { Anchor, Stack, Text } from '@mantine/core';
import { Link } from 'react-router-dom';
import type { AuditRecord } from '../api/types';
import { auditProposalId, proposalHref } from '../lib/proposalHistory';

export function AuditSubject({ record }: { record: AuditRecord }) {
  const proposal = auditProposalId(record);
  if (!proposal) return <Text size="sm" ff="monospace">{record.subject ?? '-'}</Text>;
  return <Stack gap={2}>
    {record.subject && record.subject !== proposal && <Text size="sm" ff="monospace">{record.subject}</Text>}
    <Anchor component={Link} to={proposalHref(proposal)} size="sm" ff="monospace" onClick={(event) => event.stopPropagation()}
      aria-label={`Open proposal ${proposal}`} style={{ overflowWrap: 'anywhere' }}>
      {record.subject === proposal ? proposal : `Open proposal ${proposal}`}
    </Anchor>
  </Stack>;
}
