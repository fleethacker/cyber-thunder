// "Acting as <name>" chip. The name is kept in localStorage and sent as X-Actor on every request.
import { Badge, Button, Group, Popover, Stack, Text, TextInput } from '@mantine/core';
import { IconUser } from '@tabler/icons-react';
import { useEffect, useState } from 'react';
import { useAppState } from '../state/AppState';

const RESERVED = ['agent', 'llm', 'system'];

export function actorProblem(name: string): string | null {
  const n = name.trim();
  if (!n) return 'Type your name and rate, e.g. IT1 Smith';
  if (RESERVED.includes(n.toLowerCase()) || n.toLowerCase().startsWith('policy:')) return 'That name is reserved for the machine';
  if (n.length > 128) return 'Too long';
  return null;
}

export function ActorChip() {
  const { actor, identityLocked, identityError, setActor } = useAppState();
  const [opened, setOpened] = useState(!actor && !identityLocked);
  const [draft, setDraft] = useState(actor);
  useEffect(() => setDraft(actor), [actor]);
  const problem = actorProblem(draft);

  if (identityLocked) {
    return (
      <Badge size="lg" variant={actor ? 'light' : 'filled'} color={actor ? 'indigo' : 'yellow'} tt="none" leftSection={<IconUser size={14} />}>
        {actor ? `Signed in as ${actor}` : (identityError || 'Sign in through Keycloak')}
      </Badge>
    );
  }

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
          {actor ? `Acting as ${actor}` : 'Set your name'}
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
            <Text size="sm">Every approval, denial and kill switch action is recorded under this name.</Text>
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
