import { Alert, Stack, Text } from '@mantine/core';
import type { FindingReviewEvent, RecordedPrincipalEvidence } from '../api/types';
import { useIdentity } from '../state/Identity';

const object = (value: unknown): Record<string, unknown> =>
  value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
const text = (value: unknown): string | null => typeof value === 'string' && value.trim() ? value : null;
const sourceName = (value: unknown) => value === 'oidc' ? 'OIDC' : value === 'mesh' ? 'mesh' : null;

function PrincipalDetails({ issuer, subject, roles, actor }: { issuer: string; subject: string; roles: unknown; actor: string }) {
  const names = Array.isArray(roles) && roles.every((role) => typeof role === 'string') ? roles : [];
  return <Stack gap={2} style={{ overflowWrap: 'anywhere' }}>
    <Text size="xs">Issuer: {issuer}</Text>
    <Text size="xs">Subject: {subject}</Text>
    <Text size="xs">Roles: {names.join(', ') || 'Not recorded'}</Text>
    <Text size="xs" c="dimmed">Audit actor: {actor}</Text>
  </Stack>;
}

/** Server-recorded attribution, not a fresh authentication or permission check. */
export function RecordedIdentity({ actor, evidence, verified, label, event = 'decision', humanOnly = true }: {
  actor: string | null | undefined; evidence?: RecordedPrincipalEvidence | null; verified?: boolean; label: string;
  event?: 'decision' | 'proposal creation'; humanOnly?: boolean;
}) {
  const principal = object(evidence);
  const name = text(principal.name), issuer = text(principal.iss), subject = text(principal.sub);
  const source = sourceName(principal.via);
  const policy = actor?.startsWith('policy:');
  const complete = !policy && !!text(actor) && (principal.kind === 'human' || (!humanOnly && principal.kind === 'workload')) && principal.verified === true
    && verified !== false && !!source && !!name && !!issuer && !!subject;
  return <Stack gap={2}>
    <Text size="xs">{label} {complete ? name : actor || 'Actor not recorded'}</Text>
    <Text size="xs" c={complete ? 'teal' : 'dimmed'}>{complete ? `Verified at ${event} (${source})`
      : policy ? 'Standing policy decision; signer verification is not established by this record.'
        : verified === true || principal.verified === true ? 'Identity verification unavailable: recorded evidence is incomplete or inconsistent.'
          : 'Local / unverified identity; no verified account evidence was recorded.'}</Text>
    {complete && <PrincipalDetails issuer={issuer!} subject={subject!} roles={principal.roles} actor={actor!} />}
  </Stack>;
}

export function ReviewIdentity({ event }: { event: FindingReviewEvent }) {
  return <RecordedIdentity label="Reviewed by" actor={event.reviewed_by} evidence={event.reviewed_principal}
    verified={event.identity_verified === true} />;
}

/** Session metadata labels the next reviewer only; it never upgrades an older decision. */
export function ReviewerIdentity({ actor }: { actor: string }) {
  const { identity } = useIdentity();
  if (identity.mode === 'dev') return <Alert color="blue" title="Local / unverified reviewer">
    <Text size="sm">Recorded as {actor || '(set your name in the header)'}. This local name is self-asserted; it does not authenticate an account.</Text>
  </Alert>;
  // /auth/status deliberately uses the public names source/issuer/subject, not raw claims.
  const principal = object(identity.principal);
  const name = text(principal.name), issuer = text(principal.issuer), subject = text(principal.subject);
  const source = sourceName(principal.source), auditActor = text(principal.actor);
  const complete = identity.authenticated === true && principal.verified === true
    && principal.source === identity.mode && !!name && !!issuer && !!subject && !!source && !!auditActor;
  return <Alert color={complete ? 'teal' : 'yellow'} title={complete ? 'Verified reviewer account' : 'Reviewer identity unavailable'}>
    {complete ? <Stack gap={4}>
      <Text size="sm">Signed in as {name} ({source}). The server records the reviewer identity when saving a decision.</Text>
      <PrincipalDetails issuer={issuer!} subject={subject!} roles={principal.roles} actor={auditActor!} />
    </Stack> : <Text size="sm">Verified account metadata is unavailable. The server determines whether a review can be saved.</Text>}
  </Alert>;
}
