import type { AuditRecord, ProposalPlus } from '../api/types';

export interface ProposalTimelineStep {
  key: 'start' | 'blocked' | 'before' | 'applied' | 'failed' | 'verified' | 'rolled_back';
  title: string;
  state: 'done' | 'failed' | 'pending';
  rec?: AuditRecord;
  ts?: string;
  note?: string;
}

const text = (value: unknown): string | undefined => typeof value === 'string' && value ? value : undefined;
const object = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === 'object' && !Array.isArray(value);
const canonical = (value: unknown) => JSON.stringify(value, (_key, item) => object(item)
  ? Object.fromEntries(Object.keys(item).sort().map(key => [key, item[key]])) : item);

/** Reject malformed envelopes, conflicting bindings and ambiguous sequence numbers. */
export function proposalAudit(records: unknown, proposalId: string): AuditRecord[] {
  if (!Array.isArray(records)) return [];
  const bySeq = new Map<number, AuditRecord>();
  const conflicts = new Set<number>();
  for (const r of records) {
    if (!object(r) || !Number.isSafeInteger(r.seq) || (r.seq as number) < 0
      || !text(r.action) || !text(r.outcome) || !object(r.details)
      || (r.subject != null && typeof r.subject !== 'string')
      || (r.ts !== undefined && typeof r.ts !== 'string')
      || (r.actor !== undefined && typeof r.actor !== 'string')) continue;
    const record = r as unknown as AuditRecord;
    const previous = bySeq.get(record.seq);
    if (previous && canonical(previous) !== canonical(record)) conflicts.add(record.seq);
    bySeq.set(record.seq, record);
  }
  return [...bySeq.values()].filter(r => !conflicts.has(r.seq)
    && (r.subject ? r.subject === proposalId : r.details.proposal_id === proposalId)
    && (r.details.proposal_id == null || r.details.proposal_id === proposalId))
    .sort((a, b) => a.seq - b.seq);
}

const detail = (r?: AuditRecord) => text(r?.details?.error) ?? text(r?.details?.note)
  ?? text(r?.details?.reason) ?? text(r?.details?.output) ?? text(r?.details?.evidence);
const consistentSuccess = (r: AuditRecord) => ['ok', 'rule_passed', 'health'].every(key =>
  r.details[key] === undefined || r.details[key] === true);
const ok = (r: AuditRecord) => r.outcome === 'ok' && consistentSuccess(r);
const verifyFailure = (note?: string) => !!note?.match(/^(?:verify failed:|simulated verify failure:)/);
const timestamp = (value: unknown) => typeof value === 'string' ? Date.parse(value) : NaN;
const later = (a: unknown, b: unknown) => timestamp(a) > timestamp(b);

interface Verification {
  result: 'passed' | 'failed' | 'manual' | 'unknown';
  rec?: AuditRecord;
  ts?: string;
  note?: string;
}

/** Saved states describe milestones, not a live worker or guaranteed target recovery. */
export function proposalTimeline(p: ProposalPlus, records: AuditRecord[]): ProposalTimelineStep[] {
  const recs = proposalAudit(records, p.id).filter(r =>
    (r.details.target_id == null || r.details.target_id === p.host)
    && (r.details.finding_id == null || r.details.finding_id === p.finding_id));
  const latest = (pred: (r: AuditRecord) => boolean) => [...recs].reverse().find(pred);
  const event = (action: string, pred = ok) => latest((r) => r.action === action && pred(r));
  const histories = (Array.isArray(p.history) ? p.history : []).filter(h => object(h)
    && (h.state == null || h.to == null || h.state === h.to));
  const history = (state: string) => [...histories].reverse().find((h) => (h.state ?? h.to) === state);
  const reached = (state: string) => p.state === state || !!history(state);
  const time = (state: string) => text(history(state)?.ts) ?? text(history(state)?.at);
  const applying = event('proposal.applying');
  const before = event('remediation.before_state');
  const applied = event('proposal.applied');
  const verified = event('proposal.verified');
  const failed = event('proposal.failed', (r) => r.outcome === 'failed');
  const rolled = event('proposal.rolled_back', (r) => (r.outcome === 'reverted' || ok(r)) && consistentSuccess(r));
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
  if (hasFailed) steps.push({ key: 'failed', title: failureNote?.startsWith('stopped before apply:')
    ? 'Stopped before apply' : 'Change failed', state: 'failed', rec: failed, ts: time('failed'), note: failureNote });

  // Select the latest check, not the latest success. Audit sequence orders receipts even
  // when clocks tie; a saved history entry may supersede one only with a later timestamp.
  const check = latest(r => r.action === 'remediation.verify'
    || (r.action === 'proposal.verified' && r.outcome === 'ok')
    || (r.action === 'proposal.failed' && r.outcome === 'failed' && verifyFailure(detail(r))));
  const savedCheck = [...histories].reverse().find(h => (h.state ?? h.to) === 'verified'
    || ((h.state ?? h.to) === 'failed' && verifyFailure(text(h.note))));
  let verification: Verification = { result: p.state === 'verified' ? 'passed' : 'unknown' };
  if (savedCheck) verification = { result: (savedCheck.state ?? savedCheck.to) === 'verified' ? 'passed' : 'failed',
    ts: text(savedCheck.ts) ?? text(savedCheck.at), note: text(savedCheck.note) };
  const knownLaterCheck = verification.result === 'passed' && verified && check && verified.seq < check.seq;
  if (check && (knownLaterCheck || !later(verification.ts, check.ts))) {
    const passed = ok(check) && (check.action === 'proposal.verified'
      || (check.details.ok === true && check.details.rule_passed === true && check.details.health === true));
    verification = { result: passed ? 'passed' : ['failed', 'error'].includes(check.outcome) ? 'failed'
      : check.outcome === 'manual' ? 'manual' : 'unknown', rec: check, ts: text(check.ts), note: detail(check) };
  }
  const verifyPassed = verification.result === 'passed';
  const explicitVerifyFailure = verification.result === 'failed';
  const manual = verification.result === 'manual';
  // A newer attempt/result must not inherit an older restoration's completion.
  const recovery = rolled && (!rollback || rolled.seq > rollback.seq) ? rolled : rollback;
  const savedRecoveryNewer = !(rolled && recovery && rolled.seq < recovery.seq)
    && later(time('rolled_back'), recovery?.ts);
  const rollbackOK = recovery?.action === 'proposal.rolled_back'
    || (recovery?.action === 'remediation.rollback' && ok(recovery) && recovery.details.ok === true);
  const recovered = recovery ? rollbackOK || (hasRolled && savedRecoveryNewer) : hasRolled;
  const recoveryAfterCheck = recovery && !(verification.rec ? verification.rec.seq > recovery.seq
    : later(verification.ts, recovery.ts));
  const historical = verifyPassed && (hasRolled || recoveryAfterCheck);
  steps.push({ key: 'verified', title: verifyPassed ? 'Verified ✓' : explicitVerifyFailure ? 'Verification failed'
    : manual ? 'Manual verification required' : runbook && !hasFailed && !hasRolled
      ? 'Awaiting operator steps and verification' : 'Verification outcome unknown',
  state: verifyPassed ? 'done' : explicitVerifyFailure ? 'failed' : 'pending',
  rec: verification.rec, ts: verification.ts,
  note: historical ? recovered
    ? 'Historical result before rollback; current state is unconfirmed. Check the target again.'
    : 'Historical result before a recovery attempt; current state is unconfirmed. Check the target again.'
    : verification.note ?? (!verifyPassed && !explicitVerifyFailure ? 'No completed verification is confirmed by the available records.' : undefined) });

  if (recovered) {
    const receipt = savedRecoveryNewer ? undefined : recovery;
    const actor = text(receipt?.actor) ?? text(history('rolled_back')?.actor);
    steps.push({ key: 'rolled_back', title: 'Rolled back ↶', state: 'done', rec: receipt, ts: time('rolled_back'),
      note: actor ? `Recorded rollback actor: ${actor}.` : 'Rollback actor and method are not available in these records.' });
  } else if (recovery) {
    const isBlocked = recovery.outcome === 'blocked';
    const isError = recovery.action === 'proposal.rollback_error' || recovery.outcome === 'error'
      || recovery.outcome === 'failed' || recovery.details?.ok === false;
    const started = ['remediation.rollback_started', 'remediation.rollback_mutation'].includes(recovery.action) && ok(recovery);
    steps.push({ key: 'rolled_back', title: isBlocked ? 'Recovery check blocked' : isError ? 'Rollback failed'
      : started ? 'Rollback started; outcome unknown' : 'Rollback outcome unknown',
    state: isBlocked || isError ? 'failed' : 'pending', rec: recovery,
    note: detail(recovery) ?? (started ? 'A start record does not confirm that restoration ran or completed.'
      : 'Available records do not confirm a rollback attempt or completion.') });
  } else if (hasFailed) {
    steps.push({ key: 'rolled_back', title: 'Rollback outcome unknown', state: 'pending',
      note: 'Available records do not confirm a rollback attempt or completion.' });
  }
  return steps;
}
