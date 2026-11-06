// Present recorded milestones without inventing capture, verification or recovery progress.
import { Badge, Group, Text, Timeline } from '@mantine/core';
import { IconArrowBackUp, IconCamera, IconCheck, IconTool, IconX } from '@tabler/icons-react';
import { useEffect, useMemo, useState } from 'react';
import { api } from '../api/client';
import type { AuditRecord, ProposalPlus } from '../api/types';
import { fmtClock } from '../lib/format';
import { proposalAudit, proposalTimeline } from '../lib/proposalTimeline';
import { useAuditListener } from '../state/AppState';

export function useProposalAudit(proposalId: string): AuditRecord[] {
  const [cache, setCache] = useState<{ proposalId: string; records: AuditRecord[] }>({ proposalId, records: [] });
  useEffect(() => {
    let alive = true;
    setCache((cur) => cur.proposalId === proposalId ? cur : { proposalId, records: [] });
    api.audit({ subject: proposalId, limit: 1000 })
      .then((p) => {
        if (alive) setCache((cur) => {
          // Retain conflicting envelopes so the reader can quarantine their sequence;
          // choosing one here could turn an ambiguous receipt into a success.
          const records = [...(Array.isArray(p.records) ? p.records : []), ...(cur.proposalId === proposalId ? cur.records : [])];
          return { proposalId, records };
        });
      })
      .catch(() => { /* unavailable audit leaves only recorded history and live evidence */ });
    return () => { alive = false; };
  }, [proposalId]);
  useAuditListener((r) => {
    if (proposalAudit([r], proposalId).length) {
      setCache((cur) => {
        const records = cur.proposalId === proposalId ? cur.records : [];
        return { proposalId, records: records.some((x) => JSON.stringify(x) === JSON.stringify(r)) ? records : [...records, r] };
      });
    }
  });
  // Hide the previous proposal immediately, including the render before the effect resets its cache.
  return cache.proposalId === proposalId ? proposalAudit(cache.records, proposalId) : [];
}

export function ApplyTimeline({ proposal }: { proposal: ProposalPlus }) {
  const records = useProposalAudit(proposal.id);
  return <ApplyTimelineView proposal={proposal} records={records} />;
}

export function ApplyTimelineView({ proposal, records }: { proposal: ProposalPlus; records: AuditRecord[] }) {
  const steps = useMemo(() => proposalTimeline(proposal, records), [proposal, records]);
  if (!steps.length) return null;
  return (
    <Timeline active={-1} bulletSize={26} lineWidth={2}>
      {steps.map((s) => {
        const Icon = s.state === 'failed' ? IconX : s.key === 'rolled_back' ? IconArrowBackUp
          : s.key === 'before' ? IconCamera : s.key === 'verified' && s.state === 'done' ? IconCheck : IconTool;
        const color = s.state === 'failed' ? 'red' : s.state === 'pending' ? 'gray' : s.key === 'rolled_back' ? 'violet' : 'green';
        return (
          <Timeline.Item
            key={s.key}
            data-step={s.key}
            data-state={s.state}
            bullet={<Icon size={14} />}
            color={color}
            styles={{ itemBullet: { color: `var(--mantine-color-${color}-6)`, borderColor: `var(--mantine-color-${color}-6)` } }}
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
        );
      })}
    </Timeline>
  );
}
