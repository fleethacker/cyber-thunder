import { Alert, Button, Group, Modal, Stack, Text, Textarea } from '@mantine/core';
import { useEffect, useRef, useState } from 'react';
import { api, errorText } from '../api/client';
import { authorityKey } from '../api/identity';
import type { MaintenanceStatus, ProposalPlus } from '../api/types';
import { fmtZonedTime } from '../lib/format';
import { useIdentity } from '../state/Identity';
import { usePermissions } from './PermissionGate';

export function MaintenanceNotice({ value }: { value?: MaintenanceStatus }) {
  if (!value) return <Text size="sm" c="dimmed">Maintenance schedule was not reported. Refresh before applying.</Text>;
  return <Alert color={value.allowed ? 'blue' : 'orange'} title="Maintenance schedule">
    <Text size="sm">{value.reason}</Text>
    {value.current_window && <Text size="sm">Current window: {fmtZonedTime(value.current_window.start)} to {fmtZonedTime(value.current_window.end)}. Apply must start before the end.</Text>}
    {value.next_eligible_at && <Text size="sm">Next eligible time: {fmtZonedTime(value.next_eligible_at)}</Text>}
    {value.status === 'held' && !value.next_eligible_at && <Text size="sm">No future eligible time is scheduled.</Text>}
    <Text size="xs">Window expiry does not block authorized verification or recovery of work already executed.</Text>
  </Alert>;
}

/** Each review and submission is deliberate. Failed submissions discard the review. */
export function MaintenanceOverrideButton({ proposalId, disabled }: { proposalId: string; disabled?: boolean }) {
  const permission = usePermissions();
  const { identity } = useIdentity();
  const authority = authorityKey(identity);
  const [opened, setOpened] = useState(false);
  const [review, setReview] = useState<ProposalPlus | null>(null);
  const [reason, setReason] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [accepted, setAccepted] = useState(false);
  const [busy, setBusy] = useState(false);
  const sequence = useRef(0);
  const pending = useRef(false);
  const allowed = identity.authenticated && identity.mode !== 'dev' && permission.can(['apply', 'maintenance.override']);
  const live = useRef({ authority, proposalId, allowed, disabled, opened, review, reason });
  live.current = { authority, proposalId, allowed, disabled, opened, review, reason };
  const current = () => live.current.authority === authority && live.current.proposalId === proposalId
    && live.current.opened && live.current.allowed && !live.current.disabled;
  useEffect(() => {
    setOpened(false); setReview(null); setReason(''); setError(null); setAccepted(false); setBusy(false);
    return () => { sequence.current++; pending.current = false; live.current.review = null; };
  }, [proposalId, authority]);
  const close = () => {
    sequence.current++; pending.current = false;
    live.current.review = null; live.current.opened = false;
    setOpened(false); setReview(null); setReason(''); setError(null); setAccepted(false); setBusy(false);
  };
  const requestReview = async () => {
    if (!current() || pending.current) return;
    const version = ++sequence.current;
    pending.current = true; setBusy(true); setReview(null); setReason(''); setError(null); setAccepted(false);
    try {
      const p = await api.proposal(proposalId);
      if (version !== sequence.current || !current()) return;
      if (p.id !== proposalId || p.state !== 'approved' || !p.maintenance?.override) {
        throw new Error('A maintenance override is unavailable for this account or change. Review the current proposal.');
      }
      setReview(p);
    } catch (e) { if (version === sequence.current) setError(errorText(e)); }
    finally { if (version === sequence.current) { pending.current = false; setBusy(false); } }
  };
  const submit = async () => {
    if (!current() || pending.current || !review?.maintenance?.override
      || live.current.review !== review || live.current.reason !== reason
      || reason.trim().length < 10 || reason.trim().length > 1000) return;
    const expires = Date.parse(review.maintenance.override.expires_at);
    if (!Number.isFinite(expires) || expires <= Date.now()) {
      live.current.review = null;
      setReview(null); setReason(''); setError('This review expired. Review the current change again.');
      return;
    }
    const override = { ...review.maintenance.override, reason: reason.trim() };
    const version = ++sequence.current;
    // Discard before awaiting: double clicks, authentication and rerenders cannot replay it.
    live.current.review = null;
    pending.current = true; setBusy(true); setReview(null); setReason(''); setError(null);
    try {
      await api.applyWithMaintenanceOverride(proposalId, override);
      if (version === sequence.current) setAccepted(true);
    } catch (e) { if (version === sequence.current) setError(errorText(e)); }
    finally { if (version === sequence.current) { pending.current = false; setBusy(false); } }
  };
  return <>
    {allowed && <Button variant="light" color="orange" disabled={disabled || busy} onClick={() => setOpened(true)}>Review window override</Button>}
    <Modal opened={opened} onClose={close} title="Apply outside the maintenance window">
      <Stack>
        <Text size="sm">Review this approved change, then give an operational reason. This exception lasts at most two minutes and still requires current apply authority and fresh authentication.</Text>
        {!allowed && <Alert color="orange">This account cannot request a maintenance override.</Alert>}
        {error && <Alert color="red" role="alert" title="Override request rejected">{error} No request will be resubmitted automatically. Request a fresh review before trying again.</Alert>}
        {accepted && <Alert color="blue">Apply request accepted. Execution will recheck the window and your authority; check the proposal for its final outcome.</Alert>}
        {review && <>
          <Text fw={600}>{review.title} on {review.target?.name ?? review.host}</Text>
          <Text size="sm" style={{ whiteSpace: 'pre-wrap' }}>{review.fix_preview}</Text>
          <MaintenanceNotice value={review.maintenance} />
          <Text size="sm">Review expires {fmtZonedTime(review.maintenance!.override!.expires_at)}</Text>
          <Textarea label="Operational reason for applying now" value={reason} minRows={3} maxLength={1000}
            onChange={(event) => setReason(event.currentTarget.value)} />
          <Button color="orange" disabled={disabled || !allowed || busy || reason.trim().length < 10}
            onClick={() => void submit()}>Apply once with this reason</Button>
        </>}
        <Group>
          {!review && !accepted && <Button variant="light" disabled={disabled || !allowed || busy} loading={busy}
            onClick={() => void requestReview()}>Review current change</Button>}
          <Button variant="subtle" onClick={close}>Close</Button>
        </Group>
      </Stack>
    </Modal>
  </>;
}
