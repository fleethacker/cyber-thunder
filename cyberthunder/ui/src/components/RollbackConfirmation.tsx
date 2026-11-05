import { Alert, Button, Group, Modal, Stack, Text } from '@mantine/core';
import type { ProposalPlus } from '../api/types';
import { fmtZonedTime } from '../lib/format';
import { canRequestRollback } from '../lib/proposalHistory';
import { DiffButton, RollbackGuardView, rollbackGuardProblem, useProposalDiff } from './ProposalDiff';
import { ErrorBox, Loading } from './common';

export function RollbackConfirmation({ proposal, busy, blockedReason, error, onConfirm, onClose }: {
  proposal: ProposalPlus | null;
  busy: boolean;
  blockedReason: string | null;
  error: string | null;
  onConfirm: () => void;
  onClose: () => void;
}) {
  const eligible = !!proposal && canRequestRollback(proposal);
  const checks = useProposalDiff(proposal?.id ?? null);
  const guardProblem = rollbackGuardProblem(checks.data?.rollback_guard);
  const canConfirm = eligible && !busy && !blockedReason && !checks.loading && !checks.error && !guardProblem;
  return <Modal opened={!!proposal} onClose={() => { if (!busy) onClose(); }} closeOnClickOutside={!busy} closeOnEscape={!busy}
    withCloseButton={!busy} title="Roll back this change?" centered>
    {proposal && <Stack gap="md">
      <Text fw={600}>{proposal.title} on {proposal.target?.name ?? proposal.host}</Text>
      <Text size="sm">Proposal {proposal.id} · created {fmtZonedTime(proposal.created_at)}</Text>
      <Alert color="orange" title="Review newer changes first">
        Rollback uses saved state from before this change. It may overwrite newer external work on the same files or settings, and may restore the original vulnerability. Later recorded changes on this target block restoration. A recorded snapshot does not guarantee a complete restore.
      </Alert>
      <Text size="sm" style={{ whiteSpace: 'pre-wrap' }}>{proposal.rollback_plan || 'No rollback plan was recorded for this proposal.'}</Text>
      <Text size="sm" c="dimmed">{proposal.before_state_ref ? 'A saved snapshot is recorded. The service must still check that it can be used.' : 'No saved snapshot is reported. The service may refuse rollback.'}</Text>
      {checks.loading ? <Loading what="Loading current static rollback checks" />
        : checks.error ? <ErrorBox error={checks.error} onRetry={busy ? undefined : checks.reload} />
          : <RollbackGuardView guard={checks.data?.rollback_guard} onNavigate={onClose} navigationDisabled={busy} />}
      {!checks.loading && !checks.error && <Button variant="subtle" disabled={busy} onClick={() => { if (!busy) checks.reload(); }}>Refresh checks</Button>}
      <Text size="sm">The saved diff does not inspect the live target. After rollback, check the target and run a fresh scan to establish its current condition.</Text>
      <DiffButton proposalId={proposal.id} state={proposal.state} onNavigate={onClose} navigationDisabled={busy} />
      {!eligible && <Alert color="yellow">This proposal is no longer applied or verified. Refresh its current state before choosing an action.</Alert>}
      {blockedReason && <Alert color="yellow">{blockedReason}</Alert>}
      {error && <ErrorBox error={error} />}
      <Group justify="flex-end">
        <Button variant="default" disabled={busy} onClick={() => { if (!busy) onClose(); }}>Cancel</Button>
        <Button color="violet" loading={busy} disabled={!canConfirm} onClick={() => {
          if (canConfirm) onConfirm();
        }}>Confirm rollback</Button>
      </Group>
    </Stack>}
  </Modal>;
}
