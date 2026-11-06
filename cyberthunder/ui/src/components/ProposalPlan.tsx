import { Alert, Badge, Button, Group, Modal, Paper, SimpleGrid, Stack, Text, Tooltip } from '@mantine/core';
import { MaintenanceNotice } from './ProposalMaintenance';
import { IconEye } from '@tabler/icons-react';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { api, ApiError, errorText } from '../api/client';
import type { ProposalPlan as Plan } from '../api/types';
import { fmtZonedTime, label } from '../lib/format';
import { useAppState } from '../state/AppState';
import { actorProblem } from './ActorChip';
import { CodeBlock, Collapsible, JsonView, Loading, Mono, StateBadge } from './common';

function Section({ title, children }: { title: string; children: ReactNode }) {
  return <Paper withBorder p="sm" radius="sm"><Stack gap="xs">
    <Text component="h3" size="sm" fw={700} m={0}>{title}</Text>
    {children}
  </Stack></Paper>;
}

function Metadata({ title, value, empty }: { title: string; value: unknown; empty: string }) {
  const absent = value == null || value === '' ||
    (typeof value === 'object' && Object.keys(value).length === 0);
  return <Stack gap={4}>
    <Text size="xs" fw={600}>{title}</Text>
    {absent ? <Text size="sm" c="dimmed">{empty}</Text> :
      typeof value === 'string' ? <CodeBlock code={value} /> : <JsonView value={value} />}
  </Stack>;
}

function Steps({ steps, empty }: { steps: string[]; empty: string }) {
  if (!steps.length) return <Text size="sm" c="dimmed">{empty}</Text>;
  return <Stack component="ol" gap="xs" m={0} pl="lg">
    {steps.map((step, index) => <li key={index}><CodeBlock code={step} /></li>)}
  </Stack>;
}

function StaticNotice() {
  return <Alert color="yellow" title="Static library metadata">
    <Text size="sm">No target connection is made and no change is executed. This preview provides no host validation or guarantee of safety.</Text>
    <Text size="sm">Checks describe the library entry and recorded proposal state at generation time. They do not show whether the change will work on the host.</Text>
  </Alert>;
}

/** All executable content is rendered as escaped text, including commands and runbook steps. */
export function ProposalPlanView({ plan }: { plan: Plan }) {
  const { fix, target } = plan;
  const { files, dirs, commands, path_modes, path_root, ...otherCapture } = fix.before_state;
  return <Stack gap="sm">
    <StaticNotice />
    <MaintenanceNotice value={plan.maintenance} />
    <Group justify="space-between" gap="xs">
      <Text size="sm">Generated <time dateTime={plan.generated_at}>{fmtZonedTime(plan.generated_at)}</time></Text>
      <StateBadge state={plan.proposal_state} />
    </Group>
    <Section title="Target and change">
      <Group gap="xs">
        <Text fw={600} size="sm">{target.name || target.id}</Text>
        <Badge color={target.simulated ? 'grape' : 'gray'} variant="outline">{target.simulated == null ? 'Simulation unknown' : target.simulated ? 'Simulated target' : 'Not simulated'}</Badge>
        <Badge color={target.in_scope == null ? 'gray' : target.in_scope ? 'blue' : 'orange'} variant="light">{target.in_scope == null ? 'Scope unknown' : target.in_scope ? 'In scope' : 'Out of scope'}</Badge>
      </Group>
      <Text size="sm">Target ID: <Mono>{target.id}</Mono> · {target.asset_type ? label(target.asset_type) : 'Unknown target type'}</Text>
      <Text size="sm" fw={600}>{fix.title || 'No change title declared'}</Text>
      <Text size="sm"><Mono>{fix.fix_ref}</Mono> · {label(fix.kind)}</Text>
      <Text size="xs" c="dimmed">Proposal: {plan.proposal_id}</Text>
    </Section>
    <Section title="Exact proposed payload and steps">
      <Metadata title="Payload" value={fix.payload} empty="No payload declared." />
      <Text size="xs" fw={600}>Steps</Text>
      <Steps steps={fix.steps} empty="No steps declared." />
    </Section>
    <Section title="Declared capture paths and commands">
      <Text size="sm">These describe what the library asks to capture before a change. Capture paths are not a complete list of touched files. Nothing has been captured by this preview.</Text>
      <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
        <Metadata title="File paths" value={files} empty="No file capture paths declared." />
        <Metadata title="Directories and patterns" value={dirs} empty="No directory capture patterns declared." />
      </SimpleGrid>
      <Metadata title="Capture commands" value={commands} empty="No capture commands declared." />
      {(path_modes != null || path_root != null) && <>
        <Metadata title="Path mode capture command" value={path_modes} empty="No path mode capture command declared." />
        <Metadata title="Path mode rollback root" value={path_root} empty="No path mode rollback root declared." />
      </>}
      <Metadata title="Other capture metadata" value={otherCapture} empty="No other capture metadata declared." />
    </Section>
    <Section title="Verification instructions">
      <Text size="sm">Declared checks for after a change; none have run in this preview.</Text>
      {Object.keys(fix.verify).length ? Object.entries(fix.verify).map(([key, value]) =>
        <Metadata key={key} title={key === 'rule_ids' ? 'Rules to check' : label(key)} value={value} empty="No values declared." />,
      ) : <Text size="sm" c="dimmed">No verification instructions declared.</Text>}
    </Section>
    <Section title="Declared disruption">
      <Group gap="xs">
        <Badge variant="light" color={{ low: 'blue', medium: 'orange', high: 'red' }[fix.disruption] ?? 'gray'}>Disruption: {fix.disruption || 'unknown'}</Badge>
        <Text size="sm">Reboot: {fix.reboot ? 'required by library' : 'not declared as required'}</Text>
      </Group>
      <Metadata title="Service restarts" value={fix.restarts_services} empty="No service restarts declared." />
      <Text size="sm">Patch or package change: {fix.patch ? 'declared' : 'not declared'}</Text>
      <Metadata title="Risk tags" value={fix.risk_tags} empty="No risk tags declared." />
      <Metadata title="Notes" value={fix.notes} empty="No notes declared." />
    </Section>
    <Section title="Rollback">
      <Text size="sm">Library marks this change as {fix.reversible ? 'reversible' : 'not reversible'}; recovery has not been validated on the host.</Text>
      <Text size="sm">Method: {fix.rollback_kind ? label(fix.rollback_kind) : 'No rollback method declared'}</Text>
      <Metadata title="Rollback plan" value={fix.rollback_plan} empty="No rollback plan declared." />
      <Text size="xs" fw={600}>Rollback steps</Text>
      <Steps steps={fix.rollback_steps} empty="No rollback steps declared." />
    </Section>
    <Section title="Static checks">
      {plan.checks.length ? plan.checks.map((check, index) => <Stack gap={2} key={`${check.code}-${index}`}>
        <Group gap="xs">
          <Badge variant="light" color={{ pass: 'blue', blocked: 'red', unknown: 'gray' }[check.status]}>{check.status}</Badge>
          <Text size="sm" fw={600}>{label(check.code)}</Text>
        </Group>
        <Text size="sm" style={{ whiteSpace: 'pre-wrap' }}>{check.detail || 'No check detail provided.'}</Text>
      </Stack>) : <Text size="sm" c="dimmed">No static checks provided.</Text>}
    </Section>
    <Section title="Additional limitations">
      {plan.limitations.length ? <Stack component="ul" gap={4} m={0} pl="lg">
        {plan.limitations.map((limitation, index) => <Text component="li" size="sm" key={index}>{limitation}</Text>)}
      </Stack> : <Text size="sm" c="dimmed">No additional limitations supplied. The static preview limitations above still apply.</Text>}
    </Section>
    <Collapsible title="technical details">
      <Text size="xs">Format version {plan.version} · mode: {plan.mode}</Text>
      <Metadata title="Current fix SHA-256" value={plan.fix_sha256} empty="No fix digest supplied." />
      <Metadata title="Recorded proposal fix SHA-256" value={plan.approved_fix_sha256} empty="No proposal fix digest recorded." />
      <Metadata title="Library source" value={fix.source} empty="No library source declared." />
      <Metadata title="Applies to" value={fix.applies_to} empty="No applicability declared." />
      <Metadata title="Citations" value={fix.citations} empty="No citations declared." />
    </Collapsible>
  </Stack>;
}

function usePreviewProblem(busy?: boolean): string | null {
  const { actor, status } = useAppState();
  if (busy) return 'Wait for the current proposal action to finish.';
  if (status?.kill.engaged) return 'Preview requests are blocked while the kill switch is engaged.';
  return actorProblem(actor);
}

type Result = { proposalId: string } & (
  { phase: 'loading' } | { phase: 'ready'; plan: Plan } | { phase: 'error'; detail: string; unavailable: boolean }
);

export function ProposalPlan({ proposalId, opened, onClose, busy }: {
  proposalId: string; opened: boolean; onClose: () => void; busy?: boolean;
}) {
  const problem = usePreviewProblem(busy);
  const [result, setResult] = useState<Result | null>(null);
  const sequence = useRef(0);
  const pending = useRef<number | null>(null);
  // Opening, closing and changing identity never trigger an audited request.
  useEffect(() => {
    setResult(null);
    return () => { sequence.current++; pending.current = null; };
  }, [proposalId, opened]);
  const current = opened && result?.proposalId === proposalId ? result : null;
  const loading = current?.phase === 'loading';
  const close = () => {
    sequence.current++;
    pending.current = null;
    setResult(null);
    onClose();
  };
  const requestPlan = async () => {
    if (!opened || problem || pending.current !== null) return;
    const requestId = ++sequence.current;
    pending.current = requestId;
    setResult({ proposalId, phase: 'loading' });
    try {
      const plan = await api.plan(proposalId);
      if (requestId !== sequence.current) return;
      if (!plan || plan.version !== 1 || plan.mode !== 'static' || !plan.fix || !plan.target) {
        throw new ApiError(501, 'This server did not return a supported static preview.');
      }
      if (plan.proposal_id !== proposalId) throw new Error('The preview belongs to a different proposal. Request it again.');
      setResult({ proposalId, phase: 'ready', plan });
    } catch (error) {
      if (requestId !== sequence.current) return;
      setResult({ proposalId, phase: 'error', detail: errorText(error),
        unavailable: error instanceof ApiError && [404, 405, 501].includes(error.status) });
    } finally {
      if (pending.current === requestId) pending.current = null;
    }
  };
  return <Modal opened={opened} onClose={close} title={<Text fw={700}>Preview change: <Mono>{proposalId}</Mono></Text>} size="xl">
    {opened && <Stack gap="sm">
      {current?.phase !== 'ready' && <StaticNotice />}
      <Text size="sm">Each request, refresh or retry is audited under your acting name. This preview does not approve or apply a change.</Text>
      {problem && <Alert color="orange" title="Preview request disabled">{problem}</Alert>}
      <Group justify="space-between">
        <Button variant="light" onClick={() => void requestPlan()} loading={loading} disabled={!!problem || loading}>
          {loading ? 'Requesting preview' : current?.phase === 'ready' ? 'Refresh preview' : current?.phase === 'error' ? 'Retry preview' : 'Request preview'}
        </Button>
        <Button variant="subtle" color="gray" onClick={close}>Close</Button>
      </Group>
      <Stack gap="sm" aria-live="polite" aria-busy={loading}>
        {!current && <Text size="sm" c="dimmed">No preview requested. Request the current library metadata to review the proposed change.</Text>}
        {loading && <Loading what="Loading static preview" />}
        {current?.phase === 'error' && <Alert color={current.unavailable ? 'orange' : 'red'} role="alert"
          title={current.unavailable ? 'Preview not available' : 'Preview request failed'}>
          <Text size="sm" style={{ whiteSpace: 'pre-wrap' }}>{current.detail}</Text>
        </Alert>}
        {current?.phase === 'ready' && <ProposalPlanView plan={current.plan} />}
      </Stack>
    </Stack>}
  </Modal>;
}

/** Available in every proposal state. Requests are always explicit, including after reopening. */
export function PreviewButton({ proposalId, busy }: { proposalId: string; busy?: boolean }) {
  const [openId, setOpenId] = useState<string | null>(null);
  const problem = usePreviewProblem(busy);
  useEffect(() => setOpenId(null), [proposalId]);
  return <>
    <Tooltip label={problem || 'Review static library metadata; no target connection'}>
      <span><Button size="md" variant="light" color="gray" leftSection={<IconEye size={18} />} disabled={!!problem}
        onClick={() => { if (!problem) setOpenId(proposalId); }}>Preview change</Button></span>
    </Tooltip>
    <ProposalPlan key={proposalId} proposalId={proposalId} busy={busy} opened={openId === proposalId} onClose={() => setOpenId(null)} />
  </>;
}
