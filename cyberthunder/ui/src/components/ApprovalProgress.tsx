import { Alert, Stack, Text } from '@mantine/core';
import type { Proposal } from '../api/types';
import { approvalBlockReason, approvalProgress } from '../lib/proposalApprovals';
import { fmtZonedTime, label } from '../lib/format';
import { Collapsible } from './common';
import { RecordedIdentity } from './IdentityProvenance';

export function ApprovalProgress({ proposal: p, actor = '' }: { proposal: Proposal; actor?: string }) {
  const progress = approvalProgress(p);
  const reason = p.state === 'proposed' ? approvalBlockReason(p, actor) : null;
  if (!progress.protected) return reason ? <Alert color="orange">{reason}</Alert> : null;
  return <Stack gap="xs" aria-label="Approval progress">
    <Text fw={600}>{progress.collected} of {progress.required ?? '?'} distinct {progress.mode === 'unverified_dev' ? 'local' : 'human'} approvals recorded</Text>
    <Text size="sm">{progress.remaining === null ? 'Required count unavailable.' : `${progress.remaining} remaining.`} Server state: {label(p.state)}.</Text>
    {progress.mode === 'unverified_dev' && <Text size="sm" c="orange">Local / unverified approval rules. Typed names do not authenticate people.</Text>}
    {reason && <Alert color="orange">{reason}</Alert>}
    <Collapsible title="Approval identities and decision bindings">
      <Stack gap="sm">
        <RecordedIdentity label="Proposed by" actor={p.proposed_by} evidence={p.proposed_principal} event="proposal creation" humanOnly={false} />
        <Text size="xs">Severity recorded at proposal creation: {p.approval_requirements?.source.severity ?? 'Unavailable'}</Text>
        {(p.approvals ?? []).map(vote => <Stack gap={3} key={vote.id} style={{ overflowWrap: 'anywhere' }}>
          <RecordedIdentity label="Approval recorded by" actor={vote.actor} evidence={vote.principal} />
          <Text size="xs">{fmtZonedTime(vote.approved_at)}{vote.note ? ` · ${vote.note}` : ''}</Text>
          <Text size="xs">Assessment: {vote.assessment.status === 'reviewed' ? vote.assessment.id : 'Explicitly not assessed'}</Text>
          {vote.assessment.note && <Text size="xs">Acknowledgement: {vote.assessment.note}</Text>}
          <Text size="xs">Approved payload SHA-256: {vote.payload_sha256}</Text>
          <Text size="xs">Approval requirements SHA-256: {vote.requirements_sha256}</Text>
          <Text size="xs">Assessment association SHA-256: {vote.assessment_sha256}</Text>
        </Stack>)}
        <Text size="xs" c="dimmed">These are recorded identities and decisions. The server rechecks permissions, requirements and evidence before accepting another decision or applying a change.</Text>
      </Stack>
    </Collapsible>
  </Stack>;
}
