// Discovery placeholder: docs/DISCOVERY.md was not in this worktree when the UI was built, so this card
// calls GET /api/v1/discovery and shows its JSON, or "not available" when the route is absent.
// Replace with a real panel once the discovery API shape is fixed.
import { Badge, Button, Card, Group, Stack, Text } from '@mantine/core';
import { IconRefresh } from '@tabler/icons-react';
import { api, ApiError } from '../api/client';
import { useAsync } from '../lib/hooks';
import { ErrorBox, JsonView, Loading } from './common';

export function DiscoveryPanel() {
  const st = useAsync(async () => {
    try {
      return { available: true as const, data: await api.discovery() };
    } catch (e) {
      if (e instanceof ApiError && (e.status === 404 || e.status === 405 || e.status === 501)) return { available: false as const, data: null };
      throw e;
    }
  }, []);
  return (
    <Card withBorder radius="md" padding="md">
      <Stack gap="sm">
        <Group justify="space-between">
          <Group gap="xs">
            <Text fw={700}>Discovery</Text>
            {st.data && <Badge color={st.data.available ? 'teal' : 'gray'} variant="light">{st.data.available ? 'available' : 'not available'}</Badge>}
          </Group>
          <Button size="xs" variant="light" leftSection={<IconRefresh size={14} />} loading={st.loading} onClick={() => void st.reload()}>Refresh</Button>
        </Group>
        {st.data === undefined ? (
          st.error ? <ErrorBox error={st.error} onRetry={() => void st.reload()} /> : <Loading what="Asking the discovery service" />
        ) : st.data.available ? (
          <JsonView value={st.data.data} maxHeight={300} />
        ) : (
          <Text size="sm" c="dimmed">Network discovery is not available on this build (GET /api/v1/discovery not found). Use "Discover" on an asset row for its facts.</Text>
        )}
      </Stack>
    </Card>
  );
}
