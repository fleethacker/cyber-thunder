import { Button, Group, Paper, Stack, Text } from '@mantine/core';
import { useState, type ComponentProps } from 'react';
import { api } from '../api/client';
import { REVIEW_LABELS } from '../lib/findingAssurance';
import { fmtTime } from '../lib/format';
import { useAsync } from '../lib/hooks';
import { ErrorBox } from './common';
import { ReviewBadge } from './FindingAssurance';
import { FindingReviewPanel } from './FindingReviewPanel';
import { PermissionButton, usePermissions } from './PermissionGate';
import { ReviewIdentity } from './IdentityProvenance';

/** Keep recorded review evidence readable without mounting an editor that can submit a decision. */
export function FindingReviewAccess(props: ComponentProps<typeof FindingReviewPanel>) {
  const permission = usePermissions();
  if (permission.can('review')) return <FindingReviewPanel {...props} />;
  return <ReadOnlyReview finding={props.finding} />;
}

function ReadOnlyReview({ finding }: Pick<ComponentProps<typeof FindingReviewPanel>, 'finding'>) {
  const [opened, setOpened] = useState(false);
  const history = useAsync(() => opened ? api.findingReview(finding.id) : Promise.resolve(undefined), [finding.id, opened]);
  return <Paper withBorder p="md" radius="md">
    <Stack gap="sm">
      <Group justify="space-between"><Text fw={700}>Human review</Text><ReviewBadge review={finding.review} /></Group>
      {finding.review?.current && <><ReviewIdentity event={finding.review.current} /><Text size="sm">{finding.review.current.reason}</Text></>}
      <Group>
        <PermissionButton action="review" variant="light">Record review</PermissionButton>
        <Button variant="subtle" aria-expanded={opened} onClick={() => setOpened((value) => !value)}>
          {opened ? 'Hide review history' : 'Show review history'}
        </Button>
      </Group>
      {opened && <>
        {history.loading && <Text role="status">Loading review history…</Text>}
        {history.error && <ErrorBox error={history.error} onRetry={() => void history.reload()} />}
        {history.data && !history.data.history.length && <Text size="sm">No human review has been recorded.</Text>}
        {history.data?.history.slice().reverse().map((event) => <Stack key={event.id} gap={2}>
          <Text size="sm" fw={600}>{REVIEW_LABELS[event.disposition]}</Text>
          <ReviewIdentity event={event} />
          <Text size="xs">{fmtTime(event.reviewed_at)}</Text>
          <Text size="sm" style={{ whiteSpace: 'pre-wrap' }}>{event.reason}</Text>
          {event.supporting_evidence && <Text size="sm">{event.supporting_evidence}</Text>}
          <Text size="xs">Expiry: {event.expires_at ? fmtTime(event.expires_at) : 'None'}</Text>
        </Stack>)}
      </>}
    </Stack>
  </Paper>;
}
