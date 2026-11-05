// Diff for one proposal: GET /proposals/{id}/diff rendered as the apply and verify summaries plus a
// before/after view of every file the fix touched. Shown once a change has been attempted.
import { Alert, Anchor, Badge, Button, Group, Modal, Paper, SimpleGrid, Stack, Text } from '@mantine/core';
import { IconFileDiff } from '@tabler/icons-react';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api, errorText } from '../api/client';
import type { DiffFile, ProposalDiff, ProposalState, RollbackGuard } from '../api/types';
import { fmtZonedTime } from '../lib/format';
import { proposalHref } from '../lib/proposalHistory';
import { CodeBlock, ErrorBox, JsonView, Loading, Mono } from './common';

/** States that have a before-state snapshot worth comparing. */
export const DIFF_STATES: ProposalState[] = ['applied', 'verified', 'failed', 'rolled_back'];

export function hasDiff(state?: string | null): boolean {
  return !!state && (DIFF_STATES as string[]).includes(state);
}

/** Only an open view supplies an id. Discard responses from closed, replaced or retried views. */
export function useProposalDiff(proposalId: string | null) {
  const [request, setRequest] = useState({ id: proposalId, revision: 0 });
  const [result, setResult] = useState<{
    id: string; revision: number; data?: ProposalDiff; error?: string;
  }>();
  // Reset during render so a return to an earlier id cannot expose its old result, even for one render.
  if (request.id !== proposalId) setRequest({ id: proposalId, revision: request.revision + 1 });
  useEffect(() => {
    if (!proposalId || request.id !== proposalId) return;
    let active = true;
    void (async () => {
      try {
        const data = await api.diff(proposalId);
        if (data.proposal?.id !== proposalId) throw new Error('The diff response does not match this proposal. Refresh the checks.');
        if (active) setResult({ id: proposalId, revision: request.revision, data });
      } catch (error) {
        if (active) setResult({ id: proposalId, revision: request.revision, error: errorText(error) });
      }
    })();
    return () => { active = false; };
  }, [proposalId, request.id, request.revision]);
  const current = request.id === proposalId && result?.id === proposalId && result.revision === request.revision ? result : undefined;
  return {
    data: current?.data, error: current?.error,
    loading: !!proposalId && !current,
    reload: () => setRequest((value) => ({ ...value, revision: value.revision + 1 })),
  };
}

const stringList = (value: unknown): value is string[] => Array.isArray(value) && value.every((item) => typeof item === 'string');

/** Unsupported live drift coverage can be explicit; absent or incomplete static checks cannot. */
export function rollbackGuardProblem(guard: RollbackGuard | null | undefined): string | null {
  if (!guard) return 'Rollback checks are unavailable. Refresh the checks before confirming.';
  if (guard.status === 'blocked' || guard.transition_allowed === false ||
      (stringList(guard.reasons) && guard.reasons.length > 0) ||
      (stringList(guard.conflicting_proposals) && guard.conflicting_proposals.length > 0)) {
    return 'Rollback is blocked by the current static checks.';
  }
  if (!['not_checked', 'checked_files', 'limited'].includes(guard.status) ||
      !['files', 'partial', 'unsupported'].includes(guard.coverage) ||
      typeof guard.live_checked !== 'boolean' || typeof guard.identity_bound !== 'boolean' ||
      guard.transition_allowed !== true || !stringList(guard.reasons) ||
      !stringList(guard.conflicting_proposals) || !stringList(guard.limitations)) {
    return 'Rollback checks are incomplete or unavailable. Refresh the checks before confirming.';
  }
  return null;
}

const coverageDetail: Record<RollbackGuard['coverage'], string> = {
  files: 'Captured file bytes, type, mode and ownership have a comparison baseline. This does not cover ACLs, extended attributes or unrelated host state.',
  partial: 'Only some effects have a comparison baseline. Scripts, services, runtime settings or other effects may remain unchecked.',
  unsupported: 'Live platform drift detection is unsupported. This restore may overwrite newer external changes that the guard cannot detect.',
  unavailable: 'A usable comparison baseline is unavailable. Current drift cannot be established.',
  unknown: 'Rollback coverage could not be established.',
};

export function RollbackGuardView({ guard, onNavigate, navigationDisabled = false }: {
  guard: RollbackGuard | null | undefined;
  onNavigate?: () => void;
  navigationDisabled?: boolean;
}) {
  const problem = rollbackGuardProblem(guard);
  const reasons = stringList(guard?.reasons) ? guard.reasons : [];
  const limitations = stringList(guard?.limitations) ? guard.limitations : [];
  const conflicts = stringList(guard?.conflicting_proposals) ? guard.conflicting_proposals : [];
  const historical = guard?.last_preflight;
  return <Paper withBorder radius="sm" p="sm">
    <Stack gap="xs">
      <Text size="sm" fw={700}>Current static rollback checks</Text>
      {problem && <Alert color="orange">{problem}</Alert>}
      <Group gap="xs">
        <Badge color={problem ? 'orange' : 'gray'} variant="light">Status: {guard?.status ?? 'unknown'}</Badge>
        <Badge color="gray" variant="outline">Coverage: {guard?.coverage ?? 'unknown'}</Badge>
      </Group>
      <Text size="sm">{coverageDetail[guard?.coverage ?? 'unknown'] ?? coverageDetail.unknown}</Text>
      <Text size="sm">Endpoint identity: {guard?.identity_bound === true ? 'recorded binding' : guard?.identity_bound === false ? 'no recorded binding' : 'unknown'}.</Text>
      <Text size="sm">Transition: {guard?.transition_allowed === true ? 'eligible for engine checks' : guard?.transition_allowed === false ? 'not allowed' : 'unknown'}.</Text>
      <Text size="sm">Live comparison reported: {guard?.live_checked === true ? 'covered files only' : guard?.live_checked === false ? 'not performed' : 'unknown'}.</Text>
      <Text size="sm" fw={600}>Reasons</Text>
      {reasons.length > 0 ? <ul style={{ margin: 0, paddingLeft: 20 }}>{reasons.map((reason, i) => <li key={i}><Text size="sm">{reason}</Text></li>)}</ul>
        : <Text size="sm">{problem ? 'No additional reasons were returned.' : 'No static blockers reported. External drift may still be unknown.'}</Text>}
      {conflicts.length > 0 && <Stack gap={4}>
        <Text size="sm" fw={600}>Conflicting proposals</Text>
        {conflicts.map((id) => <Anchor key={id} component={Link} to={proposalHref(id)} size="sm"
          aria-label={`Open proposal ${id}`} aria-disabled={navigationDisabled || undefined} tabIndex={navigationDisabled ? -1 : undefined}
          style={{ overflowWrap: 'anywhere' }} onClick={(event) => {
            if (navigationDisabled) event.preventDefault();
            else onNavigate?.();
          }}>{id}</Anchor>)}
      </Stack>}
      <Text size="sm" fw={600}>Limitations</Text>
      {limitations.length > 0 ? <ul style={{ margin: 0, paddingLeft: 20 }}>{limitations.map((item, i) => <li key={i}><Text size="sm">{item}</Text></li>)}</ul>
        : <Text size="sm">No additional limitations were returned. This does not establish complete coverage.</Text>}
      <Text size="sm" c="dimmed">This view reads saved records and current static checks without connecting to the target. Later recorded changes on this target block restoration. The engine repeats its checks at restore time; external drift may remain unknown.</Text>
      {historical && <Paper withBorder p="xs">
        <Text size="sm" fw={600}>Last preflight (historical)</Text>
        <Text size="sm">{historical.checked_at ? fmtZonedTime(historical.checked_at) : 'Time not recorded'} · {historical.status} · coverage: {historical.coverage}</Text>
        {stringList(historical.reasons) && historical.reasons.map((reason, i) => <Text size="sm" key={i}>{reason}</Text>)}
        <Text size="sm" c="dimmed">This records an earlier attempt. It does not authorize a rollback now.</Text>
      </Paper>}
    </Stack>
  </Paper>;
}

function Outcome({ title, value }: { title: string; value: Record<string, unknown> | null | undefined }) {
  if (!value) return null;
  const ok = value.ok ?? value.success ?? value.passed;
  const summary = [value.summary, value.message, value.detail, value.reason].find((v) => typeof v === 'string') as string | undefined;
  return (
    <Paper withBorder radius="sm" p="sm">
      <Stack gap={4}>
        <Group gap="xs">
          <Text size="sm" fw={700}>{title}</Text>
          {typeof ok === 'boolean' && <Badge color={ok ? 'green' : 'red'} variant="light">{ok ? 'passed' : 'failed'}</Badge>}
        </Group>
        {summary && <Text size="sm">{summary}</Text>}
        <JsonView value={value} maxHeight={180} />
      </Stack>
    </Paper>
  );
}

function FileDiff({ f }: { f: DiffFile }) {
  return (
    <Stack gap={4}>
      <Mono>{f.path}</Mono>
      {f.diff ? (
        <CodeBlock code={f.diff} maxHeight={360} />
      ) : (
        <SimpleGrid cols={{ base: 1, md: 2 }} spacing="xs">
          <Stack gap={2}><Text size="xs" c="dimmed">before</Text><CodeBlock code={f.before_excerpt ?? '(no copy: file did not exist)'} maxHeight={300} /></Stack>
          <Stack gap={2}><Text size="xs" c="dimmed">after</Text><CodeBlock code={f.after_excerpt ?? '(no copy: file did not exist)'} maxHeight={300} /></Stack>
        </SimpleGrid>
      )}
      {f.diff === '' && <Text size="xs" c="dimmed">No difference: before and after match.</Text>}
    </Stack>
  );
}

export function ProposalDiffView({ proposalId, onNavigate, navigationDisabled }: { proposalId: string; onNavigate?: () => void; navigationDisabled?: boolean }) {
  const st = useProposalDiff(proposalId);
  if (st.error) return <ErrorBox error={st.error} onRetry={() => void st.reload()} />;
  if (!st.data) return <Loading what="Loading the diff" />;
  const d = st.data;
  return (
    <Stack gap="sm">
      <RollbackGuardView guard={d.rollback_guard} onNavigate={onNavigate} navigationDisabled={navigationDisabled} />
      <Outcome title="Apply" value={d.apply} />
      <Outcome title="Verify" value={d.verify} />
      <Outcome title="Rollback" value={d.rollback} />
      <Text size="sm" fw={700}>Files</Text>
      {d.files.length === 0 ? (
        <Text size="sm" c="dimmed">No file copies were captured for this change (the fix changes settings, not files).</Text>
      ) : (
        d.files.map((f) => <FileDiff key={f.path} f={f} />)
      )}
    </Stack>
  );
}

/** Diff button that opens the diff in a modal. Renders nothing for states without a snapshot. */
export function DiffButton({ proposalId, state, size = 'md', onNavigate, navigationDisabled }: { proposalId: string; state?: string | null; size?: 'xs' | 'sm' | 'md'; onNavigate?: () => void; navigationDisabled?: boolean }) {
  const [open, setOpen] = useState(false);
  if (!hasDiff(state)) return null;
  return (
    <>
      <Button size={size} variant="light" color="gray" leftSection={<IconFileDiff size={16} />} onClick={() => setOpen(true)}>Diff</Button>
      <Modal opened={open} onClose={() => setOpen(false)} title={<Text fw={700}>Before and after: <Mono>{proposalId}</Mono></Text>} size="xl">
        {open && <ProposalDiffView proposalId={proposalId} navigationDisabled={navigationDisabled} onNavigate={() => { setOpen(false); onNavigate?.(); }} />}
      </Modal>
    </>
  );
}
