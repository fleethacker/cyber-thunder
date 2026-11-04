// Diff for one proposal: GET /proposals/{id}/diff rendered as the apply and verify summaries plus a
// before/after view of every file the fix touched. Shown once a change has been attempted.
import { Badge, Button, Group, Modal, Paper, SimpleGrid, Stack, Text } from '@mantine/core';
import { IconFileDiff } from '@tabler/icons-react';
import { useState } from 'react';
import { api } from '../api/client';
import type { DiffFile, ProposalDiff, ProposalState } from '../api/types';
import { useAsync } from '../lib/hooks';
import { CodeBlock, ErrorBox, JsonView, Loading, Mono } from './common';

/** States that have a before-state snapshot worth comparing. */
export const DIFF_STATES: ProposalState[] = ['applied', 'verified', 'failed', 'rolled_back'];

export function hasDiff(state?: string | null): boolean {
  return !!state && (DIFF_STATES as string[]).includes(state);
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

export function ProposalDiffView({ proposalId }: { proposalId: string }) {
  const st = useAsync<ProposalDiff>(() => api.diff(proposalId), [proposalId]);
  if (st.error) return <ErrorBox error={st.error} onRetry={() => void st.reload()} />;
  if (!st.data) return <Loading what="Loading the diff" />;
  const d = st.data;
  return (
    <Stack gap="sm">
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
export function DiffButton({ proposalId, state, size = 'md' }: { proposalId: string; state?: string | null; size?: 'xs' | 'sm' | 'md' }) {
  const [open, setOpen] = useState(false);
  if (!hasDiff(state)) return null;
  return (
    <>
      <Button size={size} variant="light" color="gray" leftSection={<IconFileDiff size={16} />} onClick={() => setOpen(true)}>Diff</Button>
      <Modal opened={open} onClose={() => setOpen(false)} title={<Text fw={700}>Before and after: <Mono>{proposalId}</Mono></Text>} size="xl">
        {open && <ProposalDiffView proposalId={proposalId} />}
      </Modal>
    </>
  );
}
