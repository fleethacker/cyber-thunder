import { Badge, Button, CopyButton, Group, Popover, Stack, Text } from '@mantine/core';
import type { FindingConfidence, FindingReview } from '../api/types';
import { CONFIDENCE_LABELS, isSuppressed, isRemediationHeld, REVIEW_LABELS, reviewDisposition } from '../lib/findingAssurance';
import { fmtTime } from '../lib/format';
import { Collapsible, JsonView } from './common';

export function ConfidenceBadge({ confidence }: { confidence?: FindingConfidence | null }) {
  const grade = confidence?.grade ?? 'unknown';
  const reason = confidence?.reason || 'Evidence confidence has not been reported by this server.';
  const reasons = Array.from(new Set([reason, ...(confidence?.reasons ?? [])]));
  return (
    <Popover width={360} position="bottom-start" withArrow trapFocus>
      <Popover.Target>
        <Button variant="light" color={grade === 'high' ? 'teal' : grade === 'medium' ? 'blue' : grade === 'low' ? 'yellow' : 'gray'}
          size="compact-xs" aria-label={`${CONFIDENCE_LABELS[grade]} confidence: show reasons`}>{CONFIDENCE_LABELS[grade]}</Button>
      </Popover.Target>
      <Popover.Dropdown style={{ maxWidth: 'calc(100vw - 40px)' }}>
        <Stack gap="xs">
          <Text fw={600}>Why confidence is {CONFIDENCE_LABELS[grade].toLowerCase()}</Text>
          <Text size="xs" c="dimmed">Confidence describes the strength of the evidence. Severity describes impact; a human review records a decision.</Text>
          {reasons.map((r) => <Text key={r} size="sm">{r}</Text>)}
          {confidence && <>
            <Text size="xs" c="dimmed">Observed: {confidence.observed_at ? fmtTime(confidence.observed_at) : 'Not recorded'} · Assessed: {fmtTime(confidence.assessed_at)}</Text>
            <Collapsible title="collection details"><JsonView value={confidence.evidence} maxHeight={180} /></Collapsible>
          </>}
          <CopyButton value={reasons.join('\n')}>{({ copied, copy }) => <Button size="xs" variant="subtle" onClick={copy}>{copied ? 'Reasons copied' : 'Copy reasons'}</Button>}</CopyButton>
        </Stack>
      </Popover.Dropdown>
    </Popover>
  );
}

export function ReviewBadge({ review, onClick }: { review?: FindingReview | null; onClick?: () => void }) {
  const disposition = reviewDisposition(review);
  const color = isSuppressed(review) ? 'orange' : disposition === 'confirmed' ? 'blue' : 'gray';
  return <Group gap={4}>
    {onClick ? <Button variant="light" size="compact-xs" color={color} onClick={onClick}
      aria-label={`${REVIEW_LABELS[disposition]}: open human review and history`}>{REVIEW_LABELS[disposition]}</Button>
      : <Badge color={color} variant="light">{REVIEW_LABELS[disposition]}</Badge>}
    {isSuppressed(review) && <Badge size="xs" variant="outline" color="orange">Suppressed</Badge>}
    {isRemediationHeld(review) && <Badge size="xs" variant="outline" color="orange">Remediation held</Badge>}
    {review?.risk_acceptance_status && !['none', 'active'].includes(review.risk_acceptance_status) &&
      <Badge size="xs" variant="outline">Risk acceptance {review.risk_acceptance_status}</Badge>}
  </Group>;
}
