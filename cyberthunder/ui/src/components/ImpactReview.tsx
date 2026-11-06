import { Alert, Badge, Button, Checkbox, Group, Modal, Stack, Text, Textarea } from '@mantine/core';
import { useEffect, useRef, useState } from 'react';
import { api, errorText } from '../api/client';
import type { ImpactReceipt, ProposalPlus } from '../api/types';
import { fmtZonedTime, label } from '../lib/format';
import { approvalBlockReason, approvalReceiptOnly, fixedApprovalAssessment } from '../lib/proposalApprovals';
import { useAppState } from '../state/AppState';
import { actorProblem } from './ActorChip';
import { Collapsible, JsonView } from './common';
import { ApprovalProgress } from './ApprovalProgress';
import { usePermissions } from './PermissionGate';

function Items({ title, items }: { title: string; items: string[] }) {
  if (!items.length) return null;
  return <Stack gap={4}><Text fw={600}>{title}</Text><Stack component="ul" gap={4} m={0} pl="lg">
    {items.map((text, i) => <li key={i}><Text size="sm">{text}</Text></li>)}
  </Stack></Stack>;
}

export function ImpactDetails({ receipt, historical = false, fixed = false }: { receipt: ImpactReceipt; historical?: boolean; fixed?: boolean }) {
  const a = receipt.assessment;
  return <Stack gap="sm">
    <Group><Badge color={{ unknown: 'gray', low: 'blue', medium: 'orange', high: 'red', critical: 'red' }[a.risk_level]}>
      Disruption risk: {a.risk_level}</Badge>
      <Badge variant="outline">{receipt.evidence_packet.mode === 'live' ? 'Read-only collection' : 'Stored declarations only'}</Badge>
    </Group>
    <Text size="sm">{a.summary}</Text>
    <Text size="sm" fw={600}>{receipt.model.used && receipt.model.validated
      ? `Model interpretation: ${receipt.model.backend ?? 'configured model'} / ${receipt.model.name ?? 'not recorded'}`
      : `Deterministic assessment; model not used (${label(receipt.model.fallback_reason ?? 'unavailable')}).`}</Text>
    <Text size="xs" c="dimmed">Evidence collected {fmtZonedTime(receipt.evidence_packet.generated_at)} · assessment saved {fmtZonedTime(receipt.generated_at)} · review expires {fmtZonedTime(receipt.valid_until)}</Text>
    {receipt.model.used && receipt.model.input_coverage?.limited && <Text size="sm" c="orange">The model reviewed a bounded subset of the collected evidence. The full recorded risks and unknowns remain below.</Text>}
    {receipt.freshness.stale && <Alert color="orange" title={historical ? 'Historical assessment' : 'Assessment needs refreshing'}>
      {receipt.freshness.reasons.map(label).join('; ')}. {historical
        ? 'This receipt records the earlier decision and does not describe current readiness.'
        : fixed ? 'Create a new proposal and collect fresh approvals for a new assessment.'
          : 'Collect another assessment before attaching it to a decision.'}
    </Alert>}
    <Alert color="yellow" title="Limited evidence">
      This assessment is advisory. It does not prove the change will succeed. Unobserved dependencies and later target changes can affect the outcome.
    </Alert>
    <Items title="What could be disrupted" items={a.risks.map(r => `${label(r.severity)}: ${r.summary} (${r.deterministic ? 'collected or declared evidence' : 'model interpretation'})`)} />
    <Items title="Observed relationships" items={a.dependencies.map(d => `${d.from} ${label(d.relation)} ${d.to}`)} />
    <Items title="Unknowns to resolve" items={a.unknowns} />
    <Items title="Checks before the change" items={a.required_checks} />
    <Items title="Rollback limitations" items={a.rollback_limits} />
    <Collapsible title="Evidence and receipt">
      <Text size="xs">Receipt: {receipt.id}</Text>
      <Text size="xs">Fix digest: {receipt.fix_sha256}</Text>
      {receipt.evidence_packet.evidence.map(e => <Stack gap={2} key={e.id}>
        <Text size="sm" fw={600}>{e.subject} · {label(e.kind)}</Text>
        <Text size="xs">{e.source} · {fmtZonedTime(e.observed_at)} · {e.id}</Text><JsonView value={e.facts} />
      </Stack>)}
    </Collapsible>
  </Stack>;
}

export function ImpactReview({ proposal, onClose, onChanged, inspectOnly = false }: {
  proposal: ProposalPlus | null; onClose: () => void; onChanged: (p: ProposalPlus) => void; inspectOnly?: boolean;
}) {
  const { actor, status } = useAppState();
  const permission = usePermissions();
  const generation = useRef(0);
  const [receipt, setReceipt] = useState<ImpactReceipt | null>(null);
  const [loading, setLoading] = useState(false);
  const [assessing, setAssessing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [storedOnly, setStoredOnly] = useState(false);
  const [ack, setAck] = useState(false);
  const [bypass, setBypass] = useState(false);
  const [note, setNote] = useState('');
  const id = proposal?.id;
  const historical = !!proposal && !['proposed', 'approved'].includes(proposal.state);
  const receiptOnly = !!proposal && approvalReceiptOnly(proposal);
  const fixedAssessment = !!proposal && (fixedApprovalAssessment(proposal) || receiptOnly);
  const readOnly = inspectOnly || receiptOnly || historical;
  const selectedReceiptId = historical || fixedAssessment ? proposal?.assessment?.id : null;
  useEffect(() => {
    generation.current++;
    let live = true;
    setReceipt(null); setError(null); setAck(false); setBypass(false); setNote(''); setStoredOnly(false);
    if (!id) return;
    if ((historical || fixedAssessment) && !selectedReceiptId) { setLoading(false); return; }
    setLoading(true);
    const request = selectedReceiptId ? api.impactReceipt(selectedReceiptId).then(assessment => ({ assessment })) : api.latestImpact(id);
    void request.then(r => { if (live) setReceipt(r.assessment); })
      .catch(e => { if (live) setError(errorText(e)); }).finally(() => { if (live) setLoading(false); });
    return () => { live = false; };
  }, [id, historical, fixedAssessment, selectedReceiptId, proposal?.state]);
  const problem = actorProblem(actor) || (!status ? 'Node status is unavailable.' : status.kill.engaged ? 'The kill switch is engaged.' : null);
  const busy = loading || assessing || saving;
  const isApproved = proposal?.state === 'approved';
  const saveActions = [isApproved ? 'review' : 'approve', 'plan'];
  const approvalProblem = proposal?.state === 'proposed' ? approvalBlockReason(proposal, actor) : null;
  const fresh = !!receipt && receipt.proposal_id === id && (!selectedReceiptId || receipt.id === selectedReceiptId)
    && !receipt.freshness.stale && Date.parse(receipt.valid_until) > Date.now();
  const mayBypass = !isApproved && (!fixedAssessment || proposal?.assessment?.status === 'not_assessed');
  const canSave = !readOnly && !problem && !approvalProblem && permission.can(saveActions) && !busy && note.trim().length >= 10 &&
    ((bypass && mayBypass) || (!!receipt && fresh && ack));
  async function assess() {
    if (!proposal || problem || busy || historical || fixedAssessment || !permission.can('plan')) return;
    const version = generation.current;
    setAssessing(true); setError(null); setAck(false); setBypass(false);
    try { const result = await api.assessImpact(proposal.id, !storedOnly); if (version === generation.current) setReceipt(result); }
    catch (e) { setError(errorText(e)); }
    finally { setAssessing(false); }
  }
  async function save() {
    if (!proposal || !canSave || !permission.can(saveActions) || (!isApproved && approvalBlockReason(proposal, actor))) return;
    setSaving(true); setError(null);
    try {
      const result = isApproved ? await api.reviewImpact(proposal.id, receipt!.id, note.trim())
        : await api.approve(proposal.id, undefined, bypass ? undefined : receipt!.id, note.trim());
      onChanged(result); onClose();
    } catch (e) { setError(errorText(e)); }
    finally { setSaving(false); }
  }
  return <Modal opened={!!proposal} onClose={() => { if (!busy) onClose(); }} size="xl"
    closeOnClickOutside={!busy} closeOnEscape={!busy} title={inspectOnly || receiptOnly ? 'Change impact' : isApproved ? 'Review refreshed assessment' : 'Review before approval'}>
    <Stack>
      <Text fw={600}>{proposal?.title} · {proposal?.target?.name ?? proposal?.host}</Text>
      {proposal && <ApprovalProgress proposal={proposal} actor={actor} />}
      {problem && <Alert color="orange">{problem}</Alert>}
      {!readOnly && !permission.can(saveActions) && <Alert color="orange">{permission.reason(saveActions)}</Alert>}
      {error && <Alert color="red">{error}</Alert>}
      {loading && <Text>Loading saved assessment...</Text>}
      {receipt ? <ImpactDetails receipt={receipt} historical={historical} fixed={fixedAssessment} /> : !loading && <Alert color="yellow" title={error || selectedReceiptId ? 'Assessment unavailable' : 'Not assessed'}>
        {selectedReceiptId ? 'This decision has an attached assessment, but its receipt could not be displayed.'
          : error ? 'The saved assessment could not be checked. Its status is unknown.'
          : historical ? 'No dependency assessment was attached to this earlier decision.' : 'Dependency and disruption assessment has not been recorded for this proposal.'}
      </Alert>}
      {fixedAssessment && <Alert color="blue" title="Assessment bound to recorded approvals">
        {proposal?.assessment?.status === 'reviewed'
          ? 'Every approver must review this exact attached receipt. A missing, stale or changed assessment requires a new proposal and fresh approvals.'
          : 'Earlier approvals explicitly recorded no dependency assessment. Any remaining approver must make the same choice and record their own reason.'}
        {' '}To change the assessment, cancel this proposal and create a new one.
      </Alert>}
      {proposal?.assessment?.note && <Text size="sm">Recorded review note: {proposal.assessment.note}</Text>}
      {!historical && !fixedAssessment && <>
      <Checkbox label="Use stored declarations only; do not contact the target" checked={storedOnly} disabled={busy}
        onChange={e => setStoredOnly(e.currentTarget.checked)} />
      <Button loading={assessing} disabled={!!problem || loading || saving || !permission.can('plan')} onClick={() => void assess()}>
        {receipt ? 'Refresh dependency assessment' : 'Collect and assess dependencies'}
      </Button>
      {assessing && <Text size="sm">Reading bounded dependency evidence and waiting for the configured model. This can take several minutes. No fix is being applied.</Text>}
      </>}
      {!readOnly && <>
        {receipt && <Checkbox label="I reviewed the risks, unknowns, checks and rollback limitations" checked={ack}
          disabled={busy || !fresh || bypass} onChange={e => setAck(e.currentTarget.checked)} />}
        {mayBypass && <Checkbox label="Proceed without a dependency assessment and record my reason" checked={bypass}
          disabled={busy} onChange={e => { setBypass(e.currentTarget.checked); setAck(false); }} />}
        <Textarea label={bypass ? 'Reason for proceeding without assessment' : 'Review note and treatment of unresolved dependencies'}
          description="At least 10 characters; saved with the decision." required minRows={2} maxLength={2000}
          value={note} disabled={busy} onChange={e => setNote(e.currentTarget.value)} />
        <Button color="green" disabled={!canSave} loading={saving} onClick={() => void save()}>
          {isApproved ? 'Record assessment review' : bypass ? 'Approve as not assessed' : 'Approve reviewed change'}
        </Button>
      </>}
    </Stack>
  </Modal>;
}
