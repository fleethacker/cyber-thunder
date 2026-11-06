// Finding detail drawer: description, check text, evidence, fix text, citations (plain links), explanation
// (with Regenerate), the library fix entry, "Propose fix", and this finding's proposal history.
import { Badge, Drawer, Group, Paper, Stack, Table, Text, Title } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { IconRefresh, IconSend } from '@tabler/icons-react';
import { useState, type ReactNode } from 'react';
import { PermissionButton, usePermissions } from './PermissionGate';
import { api, errorText } from '../api/client';
import type { FindingPlus, ProposalPlus } from '../api/types';
import { fmtAgo, fmtTime } from '../lib/format';
import { isSuppressed, isRemediationHeld } from '../lib/findingAssurance';
import { findingResultLabel } from '../lib/findingRow';
import { useAsync } from '../lib/hooks';
import { CitationChips } from './CitationChips';
import { CodeBlock, Collapsible, ErrorBox, Loading, Mono, SeverityBadge, StateBadge, StatusBadge } from './common';
import { RiskTagsForFix } from './FixPanel';
import { DiffButton } from './ProposalDiff';
import { ConfidenceBadge } from './FindingAssurance';
import { FindingReviewAccess } from './FindingActions';
import { FindingCatalogReference } from './FindingCatalogReference';
import { FindingReassessment } from './FindingReassessment';

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Stack gap={4}>
      <Text size="xs" fw={700} c="dimmed" tt="uppercase">{title}</Text>
      {children}
    </Stack>
  );
}

function citationsOf(f: FindingPlus): string[] {
  const ids = [f.rule_id, f.rule_version, f.group_id, ...f.references.map((r) => r.id)].filter(Boolean) as string[];
  return Array.from(new Set(ids));
}

export function FindingDrawer({ findingId, onClose, onProposed, onReviewed, initialReviewOpen = false }: {
  findingId: string | null; onClose: () => void; onProposed?: (p: ProposalPlus) => void; onReviewed?: () => void; initialReviewOpen?: boolean;
}) {
  return (
    <Drawer opened={!!findingId} onClose={onClose} position="right" size="xl" title={<Text fw={700}>Finding detail</Text>}>
      {findingId && <FindingDetail key={findingId} id={findingId} onProposed={onProposed} onReviewed={onReviewed} initialReviewOpen={initialReviewOpen} />}
    </Drawer>
  );
}

function FindingDetail({ id, onProposed, onReviewed, initialReviewOpen }: {
  id: string; onProposed?: (p: ProposalPlus) => void; onReviewed?: () => void; initialReviewOpen: boolean;
}) {
  const st = useAsync(() => api.finding(id), [id]);
  const permission = usePermissions();
  const f = st.data;
  const history = useAsync(
    async () => (f ? (await api.proposals({ host: f.host })).proposals.filter((p) => p.finding_id === f.id) : []),
    [f?.id],
  );
  const [busy, setBusy] = useState<'explain' | 'propose' | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [reviewOpen, setReviewOpen] = useState(initialReviewOpen);

  if (!f) return st.error ? <ErrorBox error={st.error} onRetry={() => void st.reload()} /> : <Loading what="Loading finding" />;

  const regenerate = async () => {
    if (!permission.can('explain') || busy) return;
    setBusy('explain');
    setActionError(null);
    try {
      const ex = await api.explain(f.id, true);
      st.setData((current) => current ? { ...current, explanation: ex } : current);
      notifications.show({ message: 'Explanation regenerated' });
    } catch (e) {
      setActionError(errorText(e));
    } finally {
      setBusy(null);
    }
  };
  const propose = async () => {
    if (!permission.can('propose') || busy || isSuppressed(f.review) || isRemediationHeld(f.review)) return;
    setBusy('propose');
    setActionError(null);
    try {
      const p = await api.propose(f.id);
      notifications.show({ color: 'green', message: `Proposal ${p.id} created: it is waiting in Decisions` });
      onProposed?.(p);
      await Promise.all([st.reload(), history.reload()]);
    } catch (e) {
      setActionError(errorText(e));
    } finally {
      setBusy(null);
    }
  };

  const ex = f.explanation;
  const scannerStatus = f.scanner_status ?? f.remediated?.scan_status ?? f.status;
  const suppressed = isSuppressed(f.review);
  const held = isRemediationHeld(f.review);
  const live = f.proposal && !['denied', 'cancelled', 'verified', 'rolled_back', 'failed'].includes(f.proposal.state);
  return (
    <Stack gap="md">
      <Group gap="sm" wrap="nowrap" align="flex-start">
        <SeverityBadge severity={f.severity} size="lg" />
        <Stack gap={2}>
          <Title order={4}>{f.title}</Title>
          <Group gap={6}>
            <Text size="sm" fw={600}>{f.host}</Text>
            <Text size="xs">Scanner result:</Text><StatusBadge status={scannerStatus} />
            <Badge variant="outline" color="gray" size="sm">{f.source}</Badge>
            {f.asset_type && <Badge variant="outline" color="gray" size="sm">{f.asset_type}</Badge>}
          </Group>
          <Group gap={8}>
            {f.rule_version && <Mono>{f.rule_version}</Mono>}
            <Mono>{f.rule_id}</Mono>
            {f.group_id && <Mono>{f.group_id}</Mono>}
          </Group>
          <Text size="xs" c="dimmed">{f.benchmark ?? ''} {f.benchmark_release ?? ''} · collected {fmtTime(f.collected_at)}</Text>
        </Stack>
      </Group>

      {actionError && <ErrorBox error={actionError} />}

      <Section title="Scanner observation">
        <Group gap="xs"><Text size="sm">Original result:</Text><StatusBadge status={scannerStatus} /><Mono>{scannerStatus}</Mono></Group>
        {(f.needs_rescan || scannerStatus !== f.status) && <Group gap="xs"><Text size="sm" c={f.needs_rescan ? 'orange' : undefined}>{findingResultLabel(f)}:</Text><StatusBadge status={f.status} /></Group>}
        <Text size="xs" c="dimmed">Human review keeps this scanner observation intact.</Text>
        {f.evidence ? <CodeBlock code={f.evidence} maxHeight={220} /> : <Text size="sm" c="dimmed">No scanner evidence was recorded.</Text>}
      </Section>

      <Section title="Reassessment">
        <FindingReassessment reassessment={f.reassessment} />
      </Section>

      <Section title="Evidence confidence">
        <Group><ConfidenceBadge confidence={f.confidence} /><Text size="xs" c="dimmed">Select the badge for reasons and collection details.</Text></Group>
        <Text size="sm">{f.confidence?.reason || 'This server has not reported evidence confidence.'}</Text>
      </Section>

      <FindingReviewAccess finding={f} opened={reviewOpen} onToggle={() => setReviewOpen((o) => !o)} onFinding={st.setData} onReviewed={onReviewed} />

      <FindingCatalogReference finding={f} />

      <Section title="Citations">
        <CitationChips ids={citationsOf(f)} links />
      </Section>

      <Paper withBorder p="md" radius="md">
        <Stack gap="xs">
          <Group justify="space-between">
            <Text fw={700}>Explanation</Text>
            <PermissionButton action="explain" size="xs" variant="light" leftSection={<IconRefresh size={14} />} loading={busy === 'explain'} onClick={() => void regenerate()}>
              {ex ? 'Regenerate' : 'Generate'}
            </PermissionButton>
          </Group>
          {ex ? (
            <>
              <Text size="sm">{ex.risk}</Text>
              <Text size="sm" fs="italic">{ex.impact}</Text>
              <Text size="sm">{ex.plan}</Text>
              <CitationChips ids={ex.citations} links />
              <Text size="xs" c="dimmed">
                {ex.fallback ? 'template (no model)' : `generated by ${ex.backend}${ex.model ? `/${ex.model}` : ''}`} · {fmtAgo(ex.generated_at)}
                {ex.latency_s ? ` · ${ex.latency_s.toFixed(1)} s` : ''}
                {ex.dropped_citations.length ? ` · dropped: ${ex.dropped_citations.join(', ')}` : ''}
              </Text>
            </>
          ) : (
            <Text size="sm" c="dimmed">No explanation yet. Generate one with the local model (template fallback when the model is unavailable).</Text>
          )}
        </Stack>
      </Paper>

      {f.description && <Section title="Description"><Text size="sm" style={{ whiteSpace: 'pre-wrap' }}>{f.description}</Text></Section>}
      {f.check_text && <Section title="Check text"><Collapsible title="check text"><Text size="sm" style={{ whiteSpace: 'pre-wrap' }}>{f.check_text}</Text></Collapsible></Section>}
      {f.fix_text && <Section title="Fix text"><Collapsible title="fix text"><Text size="sm" style={{ whiteSpace: 'pre-wrap' }}>{f.fix_text}</Text></Collapsible></Section>}

      <Paper withBorder p="md" radius="md">
        <Stack gap="xs">
          <Group justify="space-between">
            <Text fw={700}>Library fix</Text>
            <PermissionButton action="propose"
              size="sm"
              leftSection={<IconSend size={16} />}
              disabled={!f.fix || !!live || f.status !== 'open' || suppressed || held}
              loading={busy === 'propose'}
              onClick={() => void propose()}
            >
              Propose fix
            </PermissionButton>
          </Group>
          {f.fix ? (
            <>
              <Group gap="xs"><Text size="sm" fw={600}>{f.fix.title}</Text><Mono>{f.fix.fix_ref}</Mono></Group>
              <RiskTagsForFix fix={f.fix} />
              <Collapsible title="exact change"><CodeBlock code={f.fix.preview} /></Collapsible>
              <Text size="xs" fw={700} c="dimmed">ROLLBACK</Text>
              <Text size="sm" style={{ whiteSpace: 'pre-wrap' }}>{f.fix.rollback_plan}</Text>
            </>
          ) : (
            <Text size="sm" c="dimmed">No vetted library fix for this rule. Remediate by hand using the fix text, then rescan.</Text>
          )}
          {live && <Text size="xs" c="dimmed">A live proposal already exists ({f.proposal?.state}).</Text>}
          {suppressed && <Text size="sm" c="orange">Propose is disabled while this human dismissal is active. {f.review?.current?.reason} Review the current evidence to reverse the dismissal.</Text>}
          {held && <Text size="sm" c="orange">Risk acceptance holds remediation. The scanner failure remains open. Use the risk review form to revoke acceptance, or reassess after expiry or changed evidence.</Text>}
        </Stack>
      </Paper>

      <Section title="Proposal history">
        {history.error && <ErrorBox error={history.error} />}
        {!history.data?.length ? (
          <Text size="sm" c="dimmed">{history.loading ? 'Loading...' : 'No proposals for this finding yet.'}</Text>
        ) : (
          <Table striped withTableBorder>
            <Table.Thead><Table.Tr><Table.Th>Proposal</Table.Th><Table.Th>State</Table.Th><Table.Th>Decided by</Table.Th><Table.Th>Created</Table.Th><Table.Th>Diff</Table.Th></Table.Tr></Table.Thead>
            <Table.Tbody>
              {history.data.map((p) => (
                <Table.Tr key={p.id}>
                  <Table.Td><Mono>{p.id}</Mono></Table.Td>
                  <Table.Td><StateBadge state={p.state} /></Table.Td>
                  <Table.Td>{p.decided_by ?? '-'}{p.decision_note ? `: ${p.decision_note}` : ''}</Table.Td>
                  <Table.Td>{fmtTime(p.created_at)}</Table.Td>
                  <Table.Td><DiffButton proposalId={p.id} state={p.state} size="xs" /></Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        )}
      </Section>
    </Stack>
  );
}
