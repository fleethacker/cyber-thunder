// Show verified account metadata, or the explicitly unverified local test name.
import { Badge, Button, Group, Popover, Stack, Text, TextInput } from '@mantine/core';
import { IconUser } from '@tabler/icons-react';
import { useEffect, useState } from 'react';
import { useAppState } from '../state/AppState';
import { useIdentity } from '../state/Identity';

const RESERVED = ['agent', 'llm', 'system'];

export function actorProblem(name: string): string | null {
  const n = name.trim();
  if (!n) return 'Type your name and rate, e.g. IT1 Smith';
  if (RESERVED.includes(n.toLowerCase()) || n.toLowerCase().startsWith('policy:')) return 'That name is reserved for the machine';
  if (n.length > 128) return 'Too long';
  return null;
}

export function ActorChip() {
  const { identity, logout } = useIdentity();
  const { actor, setActor } = useAppState();
  const [opened, setOpened] = useState(!actor);
  const [draft, setDraft] = useState(actor);
  useEffect(() => setDraft(actor), [actor]);
  const problem = actorProblem(draft);

  if (identity.mode !== 'dev') return <Popover position="bottom-end" withArrow>
    <Popover.Target><Button variant="subtle" size="compact-sm" leftSection={<IconUser size={14} />}>
      {identity.principal?.name ?? 'Signed in'}
    </Button></Popover.Target>
    <Popover.Dropdown><Stack gap="xs" maw={280}>
      <Badge color="teal">Verified account</Badge>
      <Text size="sm">{identity.principal?.name}</Text>
      <Text size="xs" c="dimmed">Roles: {identity.principal?.roles.join(', ') || 'No roles assigned'}</Text>
      <Text size="xs">Access to each environment and target follows its assigned permissions.</Text>
      <Button variant="default" size="xs" onClick={() => void logout()}>Sign out</Button>
    </Stack></Popover.Dropdown>
  </Popover>;

  return (
    <Popover opened={opened} onChange={setOpened} position="bottom-end" withArrow trapFocus>
      <Popover.Target>
        <Badge
          size="lg"
          variant={actor ? 'light' : 'filled'}
          color={actor ? 'indigo' : 'yellow'}
          tt="none"
          leftSection={<IconUser size={14} />}
          style={{ cursor: 'pointer' }}
          onClick={() => setOpened((o) => !o)}
          role="button"
          aria-label="Change acting name"
        >
          {actor ? `Unverified: ${actor}` : 'Set your name (unverified)'}
        </Badge>
      </Popover.Target>
      <Popover.Dropdown>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!problem) {
              setActor(draft);
              setOpened(false);
            }
          }}
        >
          <Stack gap="xs" w={260}>
            <Text size="sm">Local test mode records this typed name. It does not authenticate an account.</Text>
            <TextInput label="Acting as" value={draft} onChange={(e) => setDraft(e.currentTarget.value)} error={draft ? problem : null} data-autofocus />
            <Group justify="flex-end">
              <Button type="submit" size="xs" disabled={!!problem}>Save</Button>
            </Group>
          </Stack>
        </form>
      </Popover.Dropdown>
    </Popover>
  );
}
