// Settings: actor, model status, standing approval policy, link emulation, content updates, demo controls.
import { Alert, Badge, Button, Card, Group, Paper, SimpleGrid, Stack, Switch, Text, TextInput } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { IconFlask } from '@tabler/icons-react';
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api, errorText } from '../api/client';
import { actorProblem } from '../components/ActorChip';
import { ErrorBox, Loading, PageTitle } from '../components/common';
import { LinkControls } from '../components/LinkControls';
import { PolicyEditor } from '../components/PolicyEditor';
import { useAsync } from '../lib/hooks';
import { useAppState } from '../state/AppState';
import { useIdentity } from '../state/Identity';

function ActorCard() {
  const { identity, logout } = useIdentity();
  const { actor, setActor } = useAppState();
  const [draft, setDraft] = useState(actor);
  useEffect(() => setDraft(actor), [actor]);
  const problem = actorProblem(draft);
  if (identity.mode !== 'dev') return <Card withBorder radius="md"><Stack gap="xs">
    <Text fw={700}>Signed-in account</Text>
    <Text>{identity.principal?.name}</Text>
    <Badge color="teal" w="fit-content">Verified by the identity provider</Badge>
    <Text size="sm">Roles: {identity.principal?.roles.join(', ') || 'No roles assigned'}. Your permissions can differ by environment and target.</Text>
    <Text size="sm" c="dimmed">Target accounts are assigned by policy for each operation. App administration does not grant target administrator access.</Text>
    <Button variant="default" w="fit-content" onClick={() => void logout()}>Sign out</Button>
  </Stack></Card>;
  return (
    <Card withBorder radius="md">
      <form onSubmit={(e) => { e.preventDefault(); if (!problem) { setActor(draft); notifications.show({ message: `Acting as ${draft.trim()}` }); } }}>
        <Stack gap="xs">
          <Text fw={700}>Local test identity (unverified)</Text>
          <Text size="sm" c="dimmed">This typed name labels the audit in local test mode. It is not a verified login. Configure organization sign-in before granting shared access.</Text>
          <Group align="flex-end">
            <TextInput value={draft} onChange={(e) => setDraft(e.currentTarget.value)} placeholder="IT1 Smith" error={draft ? problem : null} w={260} />
            <Button type="submit" disabled={!!problem || draft.trim() === actor}>Save</Button>
          </Group>
        </Stack>
      </form>
    </Card>
  );
}

function ModelCard() {
  const { status } = useAppState();
  const restricted = status?.global_details === false;
  const llm = restricted ? null : status?.llm;
  return (
    <Card withBorder radius="md">
      <Stack gap="xs">
        <Text fw={700}>Local model</Text>
        {!llm ? <Text size="sm" c="dimmed">{restricted ? 'Model status is restricted for this account.' : 'Model status is unknown.'}</Text> : (
          <>
            <Group gap="xs">
              <Badge color={llm.available ? 'blue' : 'yellow'} variant="light">{llm.available ? 'available' : 'fallback: template'}</Badge>
              <Text ff="monospace" size="sm">{llm.backend}{llm.model ? ` / ${llm.model}` : ''}</Text>
              {llm.queue !== undefined && <Text size="sm" c="dimmed">queue {llm.queue}</Text>}
            </Group>
            {llm.detail && <Text size="sm" c="dimmed">{llm.detail}</Text>}
            <Text size="xs" c="dimmed">The model only explains and cites. It never writes or runs a fix. Backend is set on the server (CT_LLM_* environment).</Text>
          </>
        )}
      </Stack>
    </Card>
  );
}

function DemoControls() {
  const st = useAsync(() => api.demo(), []);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const act = async (what: string, fn: () => Promise<unknown>, ok: string) => {
    setBusy(what);
    setError(null);
    try {
      await fn();
      notifications.show({ message: ok });
      await st.reload();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(null);
    }
  };
  return (
    <Paper withBorder p="md" radius="md" style={{ borderColor: 'var(--mantine-color-grape-6)' }}>
      <Stack gap="sm">
        <Group gap="xs"><IconFlask size={18} /><Text fw={700}>Demonstration controls</Text></Group>
        {st.data === undefined ? (st.error ? <ErrorBox error={st.error} onRetry={() => void st.reload()} /> : <Loading />) : !st.data.available ? (
          <Text size="sm" c="dimmed">The simulated range is not part of this build.</Text>
        ) : (
          <>
            <Text size="sm">Simulated range: {st.data.loaded ? `${st.data.targets.length} simulated targets loaded` : 'not loaded'}.</Text>
            <Group gap="sm">
              <Button variant="light" loading={busy === 'load'} onClick={() => void act('load', api.demoLoad, 'Simulated range loaded')}>Load simulated range</Button>
              <Button variant="light" color="orange" loading={busy === 'reset'} disabled={!st.data.loaded} onClick={() => void act('reset', api.demoReset, 'Simulated hosts reset to their seeded state')}>Reset to seeded state</Button>
            </Group>
            <Alert color="grape" variant="light" title="Demonstration control">
              <Switch
                label="Force verification failure on the next apply (shows automatic rollback)"
                checked={st.data.simulate_verify_fail_next}
                disabled={busy === 'toggle'}
                onChange={(e) => { const v = e.currentTarget.checked; void act('toggle', () => api.demoToggle(v), v ? 'Next apply will fail verification and roll back' : 'Forced failure disarmed'); }}
                color="grape"
              />
              <Text size="xs" mt={4}>Audited as a demonstration action. Never used on a real asset.</Text>
            </Alert>
          </>
        )}
        {error && <ErrorBox error={error} />}
      </Stack>
    </Paper>
  );
}

export default function Settings() {
  const { status } = useAppState();
  const restricted = status?.global_details === false;
  return (
    <Stack gap="lg">
      <PageTitle title="Settings" />
      <SimpleGrid cols={{ base: 1, md: 2 }}>
        <ActorCard />
        <ModelCard />
      </SimpleGrid>
      {restricted || status?.policy.enabled == null
        ? <UnavailableSetting title="Standing approval policy" restricted={restricted} />
        : <Paper withBorder p="md" radius="md"><PolicyEditor /></Paper>}
      {restricted || !status?.link ? <UnavailableSetting title="Link observations and controls" restricted={restricted} /> : <LinkControls />}
      <Card withBorder radius="md">
        <Group justify="space-between">
          <Stack gap={4}>
            <Text fw={700}>STIG Library</Text>
            <Text size="sm" c="dimmed">Manage local releases, product subscriptions, update checks and offline imports.</Text>
          </Stack>
          <Button component={Link} to="/content" variant="light">Open STIG Library</Button>
        </Group>
      </Card>
      {restricted || !status ? <UnavailableSetting title="Demonstration controls" restricted={restricted} /> : <DemoControls />}
    </Stack>
  );
}

function UnavailableSetting({ title, restricted }: { title: string; restricted: boolean }) {
  return <Paper withBorder p="md" radius="md"><Stack gap="xs">
    <Group><Text fw={700}>{title}</Text><Badge color="gray" variant="light">{restricted ? 'Restricted' : 'Unknown'}</Badge></Group>
    <Text size="sm" c="dimmed">{restricted ? 'Node-wide details are not available to this account.' : 'Node status did not report these details.'}</Text>
  </Stack></Paper>;
}
