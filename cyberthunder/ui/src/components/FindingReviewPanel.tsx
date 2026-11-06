import { Alert, Button, Checkbox, Group, Paper, Select, Stack, Text, Textarea, TextInput } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useCallback, useEffect, useRef, useState } from 'react';
import { api, ApiError, errorText } from '../api/client';
import { authorityRevision } from '../api/identity';
import type { FindingPlus, FindingReview, FindingReviewHistory, ReviewDisposition } from '../api/types';
import { isSuppressed, isRemediationHeld, needsExpiry, REVIEW_LABELS, reviewDraft, reviewInput } from '../lib/findingAssurance';
import { fmtTime } from '../lib/format';
import { useAppState } from '../state/AppState';
import { actorProblem } from './ActorChip';
import { CodeBlock, Collapsible, ErrorBox, JsonView } from './common';
import { ReviewBadge } from './FindingAssurance';
import { ReviewIdentity, ReviewerIdentity } from './IdentityProvenance';
import { usePermissions } from './PermissionGate';

function sameReviewBasis(a: FindingReview, b: FindingReview): boolean {
  return a.revision === b.revision && a.evidence_fingerprint === b.evidence_fingerprint
    && a.active === b.active && a.disposition === b.disposition && a.reopened_reason === b.reopened_reason;
}

export function FindingReviewPanel({ finding, opened, onToggle, onFinding, onReviewed }: {
  finding: FindingPlus; opened: boolean; onToggle: () => void;
  onFinding: (finding: FindingPlus) => void; onReviewed?: () => void;
}) {
  const { actor, status } = useAppState();
  const permission = usePermissions();
  const draftAuthority = useRef(authorityRevision());
  const [review, setReview] = useState<FindingReviewHistory>();
  const [reviewAuthority, setReviewAuthority] = useState<number | null>(null);
  const [draft, setDraft] = useState(() => reviewDraft(finding.review));
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const [fresh, setFresh] = useState(false);
  const [conflict, setConflict] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);
  // Only initial load, explicit acknowledgement and successful save advance the draft's basis.
  const draftBase = useRef<FindingReview | null>(null);
  const alive = useRef(true);
  const sequence = useRef(0);
  const callbacks = useRef({ onFinding, onReviewed });
  callbacks.current = { onFinding, onReviewed };

  useEffect(() => {
    alive.current = true;
    return () => { alive.current = false; sequence.current++; };
  }, []);

  const load = useCallback(async () => {
    const request = ++sequence.current;
    const requestedAuthority = authorityRevision();
    setLoading(true);
    setFresh(false);
    setError(null);
    try {
      const [current, history] = await Promise.all([api.finding(finding.id), api.findingReview(finding.id)]);
      if (!alive.current || request !== sequence.current || requestedAuthority !== authorityRevision()) return;
      if (!current.review || !sameReviewBasis(current.review, history)) {
        setConflict(true);
        setAcknowledged(false);
        throw new Error('The finding changed during refresh. Refresh again to review the current evidence.');
      }
      setReview(history);
      setReviewAuthority(requestedAuthority);
      callbacks.current.onFinding({ ...current, review: history });
      if (!draftBase.current) {
        setDraft(reviewDraft(history));
        draftBase.current = { ...history };
        draftAuthority.current = requestedAuthority;
      } else if (!sameReviewBasis(draftBase.current, history) || draftAuthority.current !== requestedAuthority) {
        setConflict(true);
        setAcknowledged(false);
      }
      setUnavailable(false);
      setFresh(true);
    } catch (e) {
      if (!alive.current || request !== sequence.current) return;
      if (e instanceof ApiError && [404, 405, 501].includes(e.status)) setUnavailable(true);
      else setError(errorText(e));
    } finally {
      if (alive.current && request === sequence.current) setLoading(false);
    }
  }, [finding.id]);

  useEffect(() => { if (opened) void load(); }, [opened, load]);

  const save = async () => {
    if (!review || !draftBase.current || !fresh || loading || saving || (conflict && !acknowledged)) return;
    const riskDecision = ['risk_accepted', 'risk_revoked'].includes(draft.disposition);
    if (!permission.can(riskDecision ? 'risk.accept' : 'review')) return;
    if (draftAuthority.current !== authorityRevision() || reviewAuthority !== authorityRevision()) {
      setFresh(false);
      setError('Account or permissions changed. Refresh and review the current evidence before saving.');
      return;
    }
    if (isRemediationHeld(review) && draft.disposition !== 'risk_revoked') {
      setError('Revoke the active risk acceptance before recording another decision.');
      return;
    }
    if (!sameReviewBasis(draftBase.current, review)) {
      setConflict(true);
      setAcknowledged(false);
      return;
    }
    setError(null);
    try {
      const body = reviewInput(draft, draftBase.current);
      setSaving(true);
      const { reason, expected_revision, evidence_fingerprint } = body;
      const basis = { reason, expected_revision, evidence_fingerprint };
      const requestedAuthority = authorityRevision();
      const saved = draft.disposition === 'risk_accepted'
        ? await api.acceptFindingRisk(finding.id, { ...basis, supporting_evidence: body.supporting_evidence, expires_at: body.expires_at! })
        : draft.disposition === 'risk_revoked' ? await api.revokeFindingRisk(finding.id, basis)
        : await api.saveFindingReview(finding.id, body);
      if (!alive.current || requestedAuthority !== authorityRevision()) return;
      draftBase.current = { ...saved };
      setReview(saved);
      setConflict(false);
      setAcknowledged(false);
      callbacks.current.onFinding({ ...finding, review: saved });
      callbacks.current.onReviewed?.();
      notifications.show({ color: 'green', message: 'Review recorded. The scanner result is unchanged.' });
      await load();
    } catch (e) {
      if (!alive.current) return;
      if (e instanceof ApiError && e.status === 409) {
        setConflict(true);
        setAcknowledged(false);
        notifications.show({ color: 'yellow', message: 'Review not saved: the current review or evidence changed. Your input is retained.' });
        await load();
      } else {
        setError(errorText(e));
      }
    } finally { if (alive.current) setSaving(false); }
  };

  const summary = review ?? finding.review;
  const identityProblem = actorProblem(actor);
  const basisChanged = !!review && !!draftBase.current && !sameReviewBasis(draftBase.current, review);
  const riskDecision = ['risk_accepted', 'risk_revoked'].includes(draft.disposition);
  const action = riskDecision ? 'risk.accept' : 'review';
  const held = isRemediationHeld(summary);
  const blocked = !permission.can(action) || (held && draft.disposition !== 'risk_revoked') || loading || saving || !fresh || unavailable || !!identityProblem || !!status?.kill.engaged || basisChanged || reviewAuthority !== authorityRevision() || (conflict && !acknowledged);
  return (
    <Paper withBorder p="md" radius="md">
      <Stack gap="sm">
        <Group justify="space-between">
          <Text fw={700}>Human review</Text>
          <ReviewBadge review={summary} onClick={onToggle} />
        </Group>
        <Text size="xs" c="dimmed">A review records a human decision. It does not approve a fix or change the scanner result.</Text>
        {summary?.current && <ReviewIdentity event={summary.current} />}
        {summary?.reopened_reason && <Alert color="yellow" title="Review reopened"><Text size="sm">{summary.reopened_reason}</Text><Text size="sm">Review the current evidence before recording another decision.</Text></Alert>}
        {isSuppressed(summary) && <Alert color="orange" title="New proposals are blocked">
          <Text size="sm">{summary?.current?.reason}</Text>
          <Text size="xs">This dismissal applies only to matching evidence and scope, until {summary?.current?.expires_at ? fmtTime(summary.current.expires_at) : 'its recorded expiry'}. The original scanner result is retained.</Text>
        </Alert>}
        {held && <Alert color="orange" title="Risk accepted — remediation held">
          <Text size="sm">{summary?.current?.reason}</Text>
          <Text size="sm">The scanner failure and severity remain. Proposals and apply are held until authorized revocation, expiry, or changed evidence reopens the finding. This does not approve a fix.</Text>
          <Text size="xs">Expires: {fmtTime(summary?.current?.expires_at ?? '')}</Text>
        </Alert>}
        <Button variant="subtle" size="xs" onClick={onToggle} aria-expanded={opened} style={{ alignSelf: 'flex-start' }}>
          {opened ? 'Hide review form and history' : `Review and history${summary ? ` (${summary.history_count})` : ''}`}
        </Button>
        {opened && <Stack gap="sm">
          <ReviewerIdentity actor={actor} />
          {unavailable && <Alert color="gray" title="Review service unavailable">This server may need an upgrade, or the finding may no longer be current. Unreviewed means no current human decision is available. Your input is retained.</Alert>}
          {error && <ErrorBox error={error} />}
          <Button size="xs" variant="light" loading={loading} disabled={saving} onClick={() => void load()} style={{ alignSelf: 'flex-start' }}>Refresh current evidence and history</Button>
          {conflict && <Alert color="yellow" title="Review or evidence changed">
            <Stack gap="xs">
              <Text size="sm">The evidence or review changed since this draft was prepared. Your input is retained. Check the refreshed scanner evidence, confidence and review history before saving again.</Text>
              {fresh && <>
                <Text size="sm">Current scanner observation: {finding.scanner_status ?? finding.remediated?.scan_status ?? finding.status}</Text>
                <CodeBlock code={finding.evidence || 'No scanner evidence was recorded.'} maxHeight={160} />
                <Text size="sm">Confidence: {finding.confidence?.reason || 'Not reported'}</Text>
              </>}
              <Checkbox label="I have reviewed the current evidence and review history" checked={acknowledged}
                disabled={!fresh || loading || saving} onChange={(e) => {
                  // A retained checkbox must acknowledge only the account that fetched this evidence.
                  if (!review || !fresh || loading || saving || reviewAuthority !== authorityRevision()) return;
                  const checked = e.currentTarget.checked;
                  if (checked) { draftBase.current = { ...review }; draftAuthority.current = reviewAuthority; }
                  setAcknowledged(checked);
                }} />
            </Stack>
          </Alert>}
          <form onSubmit={(e) => { e.preventDefault(); if (!blocked) void save(); }}>
            <Stack gap="sm">
              <Select label="Review decision" data={Object.entries(REVIEW_LABELS).map(([value, label]) => ({ value, label,
                disabled: !permission.can(value.startsWith('risk_') ? 'risk.accept' : 'review')
                  || (held && value !== 'risk_revoked') || (value === 'risk_revoked' && summary?.current?.disposition !== 'risk_accepted') }))}
                value={draft.disposition} allowDeselect={false} disabled={saving || !review}
                onChange={(value) => setDraft((d) => ({ ...d, disposition: (value ?? 'unreviewed') as ReviewDisposition }))} />
              {['false_positive', 'not_applicable'].includes(draft.disposition) && <Text size="sm">False positive and Not applicable temporarily suppress new proposals for this exact evidence. A reason and future expiry are required.</Text>}
              {riskDecision && <Alert color="yellow" title="Operator risk decision">
                <Text size="sm">Acceptance requires a reason, supporting evidence and future expiry within 30 days. This is a product limit, not a compliance policy. Revocation requires a reason and the same risk.accept authority.</Text>
                <Text size="sm">The server requires a human approver, an explicit account/environment/target grant and fresh authentication. Local development records an unverified fixture decision, not official enclave risk authorization.</Text>
              </Alert>}
              <Textarea label="Reason" required autosize minRows={3} value={draft.reason} disabled={saving || !review}
                placeholder="What did you check, and why does it support this decision?"
                onChange={(e) => { const reason = e.currentTarget.value; setDraft((d) => ({ ...d, reason })); }} />
              <Textarea label="Supporting evidence" description="Record observations or references that support your review." autosize minRows={2}
                required={draft.disposition === 'risk_accepted'}
                value={draft.supportingEvidence} disabled={saving || !review}
                onChange={(e) => { const supportingEvidence = e.currentTarget.value; setDraft((d) => ({ ...d, supportingEvidence })); }} />
              <TextInput type="datetime-local" label={`Expiry${needsExpiry(draft.disposition) ? ' (required)' : ' (optional)'}`}
                description="Your local date and time; stored with its time zone. Expiry reopens the review."
                required={needsExpiry(draft.disposition)} value={draft.expiresAt} disabled={saving || !review}
                onChange={(e) => { const expiresAt = e.currentTarget.value; setDraft((d) => ({ ...d, expiresAt })); }} />
              {identityProblem && <Text size="sm" c="orange">Set your acting name in the header: {identityProblem}</Text>}
              {status?.kill.engaged && <Text size="sm" c="red">The kill switch blocks review changes.</Text>}
              {!permission.can(action) && <Text size="sm" c="orange">{permission.reason(action)}</Text>}
              <Group>
                <Button type="submit" loading={saving} disabled={blocked || !draft.reason.trim()}>{draft.disposition === 'risk_accepted' ? 'Accept risk' : draft.disposition === 'risk_revoked' ? 'Revoke risk acceptance' : 'Save review'}</Button>
                {summary?.current?.disposition === 'risk_accepted' && <Button type="button" variant="light"
                  disabled={saving || !review || !permission.can('risk.accept')}
                  onClick={() => { if (permission.can('risk.accept')) setDraft((d) => ({ ...d, disposition: 'risk_revoked', reason: '', expiresAt: '' })); }}>Prepare risk revocation</Button>}
                <Button type="button" variant="light" disabled={held || saving || !review || draft.disposition === 'unreviewed'}
                  onClick={() => setDraft((d) => ({ ...d, disposition: 'unreviewed', expiresAt: '' }))}>Return to Unreviewed</Button>
              </Group>
              <Text size="xs" c="dimmed">Returning to Unreviewed requires a reason and Save review. It records a reversal and retains the earlier history.</Text>
            </Stack>
          </form>
          <Text fw={600}>Review history</Text>
          {!review?.history.length && <Text size="sm" c="dimmed">{loading ? 'Loading review history…' : review ? 'No human review has been recorded.' : 'History is unavailable until the review service responds.'}</Text>}
          {review?.history.slice().reverse().map((event) => <Paper key={event.id} withBorder p="sm" radius="sm">
            <Stack gap={4}>
              <Group justify="space-between"><Text fw={600} size="sm">{REVIEW_LABELS[event.disposition]}</Text><Text size="xs">{fmtTime(event.reviewed_at)}</Text></Group>
              <ReviewIdentity event={event} />
              <Text size="sm" style={{ whiteSpace: 'pre-wrap' }}>{event.reason}</Text>
              {event.supporting_evidence && <Text size="sm" style={{ whiteSpace: 'pre-wrap' }}>Supporting evidence: {event.supporting_evidence}</Text>}
              <Text size="xs">Expiry: {event.expires_at ? fmtTime(event.expires_at) : 'None'}</Text>
              <Collapsible title="recorded scope and evidence reference"><JsonView value={{ scope: event.scope, evidence_fingerprint: event.evidence_fingerprint }} maxHeight={160} /></Collapsible>
            </Stack>
          </Paper>)}
        </Stack>}
      </Stack>
    </Paper>
  );
}
