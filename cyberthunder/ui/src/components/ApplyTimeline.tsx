// Apply step timeline: scope check -> before-state captured -> applied -> verified, or failed -> rolled back.
// Driven by the audit records whose subject is this proposal (initial fetch + live stream) and the proposal state.
import { Badge, Group, Text, Timeline } from '@mantine/core';
import { IconArrowBackUp, IconCamera, IconCheck, IconLoader, IconShieldCheck, IconTool, IconX } from '@tabler/icons-react';
import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { api } from '../api/client';
import type { AuditRecord, ProposalPlus } from '../api/types';
import { fmtClock } from '../lib/format';
import { useAuditListener } from '../state/AppState';

interface Step {
  key: string;
  title: string;
  icon: ReactNode;
  rec?: AuditRecord;
  ts?: string;
  state: 'done' | 'active' | 'failed' | 'pending';
  note?: string;
}

const find = (recs: AuditRecord[], pred: (a: string) => boolean) => [...recs].reverse().find((r) => pred(r.action));

export function useProposalAudit(proposalId: string): AuditRecord[] {
  const [recs, setRecs] = useState<AuditRecord[]>([]);
  useEffect(() => {
    let alive = true;
    api.audit({ subject: proposalId, limit: 1000 })
      .then((p) => { if (alive) setRecs(p.records); })
      .catch(() => { /* timeline falls back to proposal history */ });
    return () => { alive = false; };
  }, [proposalId]);
  useAuditListener((r) => {
    const target = (r.details as { target?: unknown; proposal_id?: unknown }) ?? {};
    if (r.subject === proposalId || target.proposal_id === proposalId) {
      setRecs((cur) => (cur.some((x) => x.seq === r.seq) ? cur : [...cur, r]));
    }
  });
  return recs;
}

export function ApplyTimeline({ proposal }: { proposal: ProposalPlus }) {
  const recs = useProposalAudit(proposal.id);
  const steps = useMemo(() => buildSteps(proposal, recs), [proposal, recs]);
  if (!steps.length) return null;
  const active = steps.filter((s) => s.state !== 'pending').length - 1;
  return (
    <Timeline active={active} bulletSize={26} lineWidth={2}>
      {steps.map((s) => (
        <Timeline.Item
          key={s.key}
          bullet={s.icon}
          color={s.state === 'failed' ? 'red' : s.key === 'rolled_back' ? 'violet' : s.state === 'active' ? 'yellow' : 'green'}
          title={
            <Group gap="xs">
              <Text fw={600} size="sm" c={s.state === 'pending' ? 'dimmed' : undefined}>{s.title}</Text>
              {s.rec && <Badge size="xs" variant="outline" color="gray" ff="monospace">#{s.rec.seq}</Badge>}
              {(s.rec?.ts || s.ts) && <Text size="xs" c="dimmed" ff="monospace">{fmtClock(s.rec?.ts ?? s.ts)}</Text>}
            </Group>
          }
        >
          {s.note && <Text size="xs" c="dimmed">{s.note}</Text>}
        </Timeline.Item>
      ))}
    </Timeline>
  );
}

function histTs(p: ProposalPlus, state: string): string | undefined {
  const h = [...p.history].reverse().find((x) => x.state === state || x.to === state);
  return (h?.ts as string | undefined) ?? (h?.at as string | undefined);
}

function buildSteps(p: ProposalPlus, recs: AuditRecord[]): Step[] {
  const reached = new Set(p.history.map((h) => String(h.state ?? h.to ?? '')));
  reached.add(p.state);
  const started = ['applying', 'applied', 'verified', 'failed', 'rolled_back'].some((s) => reached.has(s));
  const blocked = find(recs, (a) => a === 'action.blocked');
  if (!started && !blocked) return [];

  const applying = find(recs, (a) => a === 'proposal.applying');
  const before = find(recs, (a) => /before|snapshot/.test(a));
  const applied = find(recs, (a) => a === 'proposal.applied');
  const verified = find(recs, (a) => a === 'proposal.verified');
  const failed = find(recs, (a) => a === 'proposal.failed');
  const rolled = find(recs, (a) => a === 'proposal.rolled_back');
  const has = (rec: AuditRecord | undefined, state: string) => !!rec || reached.has(state);
  const isFailed = has(failed, 'failed');
  const isRolled = has(rolled, 'rolled_back');
  const isApplied = has(applied, 'applied') || has(verified, 'verified');
  const running = p.state === 'applying';

  const steps: Step[] = [];
  steps.push({
    key: 'scope', title: blocked && !applying ? 'Scope check blocked' : 'Scope check passed',
    icon: blocked && !applying ? <IconX size={14} /> : <IconShieldCheck size={14} />,
    rec: blocked && !applying ? blocked : applying, ts: histTs(p, 'applying'),
    state: blocked && !applying ? 'failed' : 'done',
    note: blocked && !applying ? String((blocked.details as { reason?: unknown }).reason ?? blocked.outcome) : undefined,
  });
  if (blocked && !applying) return steps;

  const beforeDone = !!before || !!p.before_state_ref || isApplied || isFailed;
  steps.push({
    key: 'before', title: 'Before-state captured', icon: <IconCamera size={14} />, rec: before,
    state: beforeDone ? 'done' : running ? 'active' : 'pending',
    note: p.before_state_ref ? `snapshot ${p.before_state_ref}` : undefined,
  });

  if (isApplied || !isFailed) {
    steps.push({
      key: 'applied', title: 'Applied', icon: running && !isApplied ? <IconLoader size={14} /> : <IconTool size={14} />,
      rec: applied, ts: histTs(p, 'applied'),
      state: isApplied ? 'done' : running && beforeDone ? 'active' : 'pending',
    });
  }

  if (isFailed) {
    steps.push({
      key: 'failed', title: isApplied ? 'Verification failed' : 'Apply failed', icon: <IconX size={14} />, rec: failed,
      ts: histTs(p, 'failed'), state: 'failed',
      note: failed ? String((failed.details as { note?: unknown; error?: unknown }).error ?? (failed.details as { note?: unknown }).note ?? '') || undefined : undefined,
    });
    steps.push({
      key: 'rolled_back', title: isRolled ? 'Rolled back ↶' : 'Rolling back', icon: <IconArrowBackUp size={14} />, rec: rolled,
      ts: histTs(p, 'rolled_back'), state: isRolled ? 'done' : 'active',
    });
  } else {
    const isVerified = has(verified, 'verified');
    steps.push({
      key: 'verified', title: isVerified ? 'Verified ✓' : 'Verifying', icon: <IconCheck size={14} />, rec: verified,
      ts: histTs(p, 'verified'), state: isVerified ? 'done' : isApplied ? 'active' : 'pending',
    });
    if (isRolled) {
      steps.push({
        key: 'rolled_back', title: 'Rolled back by operator ↶', icon: <IconArrowBackUp size={14} />, rec: rolled,
        ts: histTs(p, 'rolled_back'), state: 'done',
      });
    }
  }
  return steps;
}
