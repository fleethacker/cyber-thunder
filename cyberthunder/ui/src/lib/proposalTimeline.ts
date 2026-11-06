import type { AuditRecord, ProposalPlus } from '../api/types';

export interface ProposalTimelineStep {
  key: 'start' | 'blocked' | 'before' | 'applied' | 'failed' | 'verified' | 'rolled_back';
  title: string;
  state: 'done' | 'failed' | 'pending';
  rec?: AuditRecord;
  ts?: string;
  note?: string;
}

/** A conflicting subject must never be rescued by a details field. */
export function proposalAudit(records: AuditRecord[], proposalId: string): AuditRecord[] {
  return records.filter((r) => r.subject ? r.subject === proposalId : r.details?.proposal_id === proposalId)
    .sort((a, b) => a.seq - b.seq);
}

const text = (value: unknown): string | undefined => typeof value === 'string' && value ? value : undefined;
const detail = (r?: AuditRecord) => text(r?.details?.error) ?? text(r?.details?.note)
  ?? text(r?.details?.reason) ?? text(r?.details?.output) ?? text(r?.details?.evidence);
const ok = (r: AuditRecord) => r.outcome === 'ok';

/** Saved states describe milestones, not a live worker or guaranteed target recovery. */
export function proposalTimeline(p: ProposalPlus, records: AuditRecord[]): ProposalTimelineStep[] {
  const recs = proposalAudit(records, p.id);
  const latest = (pred: (r: AuditRecord) => boolean) => [...recs].reverse().find(pred);
  const event = (action: string, pred = ok) => latest((r) => r.action === action && pred(r));
  const history = (state: string) => [...p.history].reverse().find((h) => (h.state ?? h.to) === state);
  const reached = (state: string) => p.state === state || !!history(state);
  const time = (state: string) => text(history(state)?.ts) ?? text(history(state)?.at);
  const applying = event('proposal.applying');
  const before = event('remediation.before_state');
  const applied = event('proposal.applied');
  const verified = event('proposal.verified');
  const failed = event('proposal.failed', (r) => r.outcome === 'failed');
  const rolled = event('proposal.rolled_back', (r) => r.outcome === 'reverted' || ok(r));
  const issued = event('remediation.runbook_issued');
  const verify = latest((r) => r.action === 'remediation.verify');
  const rollback = latest((r) => ['remediation.rollback_started', 'remediation.rollback_mutation',
    'remediation.rollback', 'proposal.rollback_error'].includes(r.action)
    || (r.action === 'remediation.rollback_preflight' && r.outcome === 'blocked')
    || (r.action === 'action.blocked' && r.details?.action === 'rollback'));
  const blocked = latest((r) => r.outcome === 'blocked'
    && (r.action === 'action.blocked' || r.action === 'maintenance.blocked') && r !== rollback);
  const hasFailed = reached('failed') || !!failed;
  const hasRolled = reached('rolled_back') || !!rolled;
  const hasVerified = reached('verified') || !!verified;
  const hasApplied = reached('applied') || !!applied;
  if (!['applying', 'applied', 'verified', 'failed', 'rolled_back'].some(reached)
    && !applying && !before && !applied && !verified && !failed && !rolled && !issued && !verify && !rollback && !blocked) return [];

  const steps: ProposalTimelineStep[] = [];
  if (applying || reached('applying')) steps.push({ key: 'start', title: 'Apply started', state: 'done',
    rec: applying, ts: time('applying'),
    note: p.state === 'applying' ? 'Last saved state is applying; current progress is unconfirmed.' : undefined });
  if (blocked) steps.push({ key: 'blocked', title: 'Action blocked', state: 'failed', rec: blocked, note: detail(blocked) });
  // start_apply allocates before_state_ref before capture. Only the successful receipt proves capture.
  steps.push({ key: 'before', title: before ? 'Before-state captured' : 'Before-state capture unconfirmed',
    state: before ? 'done' : 'pending', rec: before,
    note: before ? undefined : 'Available records do not confirm a completed capture.' });

  const appliedNote = text(applied?.details?.note) ?? text(history('applied')?.note);
  const runbookIssued = !!issued || !!appliedNote?.startsWith('runbook issued to operator;');
  const runbook = runbookIssued || p.fix?.kind === 'runbook';
  const payloadRecorded = hasApplied && !!appliedNote?.match(/^applied .+ on .+; changed=(?:True|False);/);
  steps.push({ key: 'applied', title: runbookIssued ? 'Runbook issued'
    : runbook ? 'Operator application unconfirmed' : payloadRecorded ? 'Application recorded' : 'Application unconfirmed',
  state: runbookIssued || (payloadRecorded && !runbook) ? 'done' : 'pending', rec: issued ?? applied, ts: time('applied'),
  note: runbook ? 'Issuing a runbook does not confirm that operator steps were completed.'
    : payloadRecorded ? appliedNote : hasApplied
      ? 'Saved state is applied, which can also mean a runbook was issued. Payload completion is unconfirmed.'
      : 'Available records do not confirm payload completion.' });

  const failureNote = detail(failed) ?? text(history('failed')?.note);
  const verifyFailed = verify?.outcome === 'failed' || verify?.outcome === 'error';
  // "error during verify" also covers post-apply capture errors. It cannot classify the failed stage.
  const explicitVerifyFailure = verifyFailed || !!failureNote?.match(/^(?:verify failed:|simulated verify failure:)/);
  if (hasFailed) steps.push({ key: 'failed', title: failureNote?.startsWith('stopped before apply:')
    ? 'Stopped before apply' : 'Change failed', state: 'failed', rec: failed, ts: time('failed'), note: failureNote });

  const rollbackOK = rollback?.action === 'remediation.rollback' && ok(rollback) && rollback.details?.ok === true;
  const verifyPassed = hasVerified || (verify?.outcome === 'ok' && verify.details?.ok === true
    && verify.details?.rule_passed === true && verify.details?.health === true);
  const manual = verify?.outcome === 'manual';
  steps.push({ key: 'verified', title: verifyPassed ? 'Verified ✓' : explicitVerifyFailure ? 'Verification failed'
    : manual ? 'Manual verification required' : runbook && !hasFailed && !hasRolled
      ? 'Awaiting operator steps and verification' : 'Verification outcome unknown',
  state: verifyPassed ? 'done' : explicitVerifyFailure ? 'failed' : 'pending',
  rec: verified ?? verify, ts: time('verified'),
  note: verifyPassed && (hasRolled || rollbackOK) ? 'Historical result before rollback; check the target again for its current state.'
    : detail(verify) ?? (!verifyPassed && !explicitVerifyFailure ? 'No completed verification is confirmed by the available records.' : undefined) });

  if (hasRolled || rollbackOK) {
    const receipt = rolled ?? (rollbackOK ? rollback : undefined);
    const actor = text(receipt?.actor) ?? text(history('rolled_back')?.actor);
    steps.push({ key: 'rolled_back', title: 'Rolled back ↶', state: 'done', rec: receipt, ts: time('rolled_back'),
      note: actor ? `Recorded rollback actor: ${actor}.` : 'Rollback actor and method are not available in these records.' });
  } else if (rollback) {
    const isBlocked = rollback.outcome === 'blocked';
    const isError = rollback.action === 'proposal.rollback_error' || rollback.outcome === 'error'
      || rollback.outcome === 'failed' || rollback.details?.ok === false;
    steps.push({ key: 'rolled_back', title: isBlocked ? 'Recovery check blocked' : isError ? 'Rollback failed'
      : 'Rollback started; outcome unknown', state: isBlocked || isError ? 'failed' : 'pending', rec: rollback,
    note: detail(rollback) ?? 'A start record does not confirm that restoration ran or completed.' });
  } else if (hasFailed) {
    steps.push({ key: 'rolled_back', title: 'Rollback outcome unknown', state: 'pending',
      note: 'Available records do not confirm a rollback attempt or completion.' });
  }
  return steps;
}
