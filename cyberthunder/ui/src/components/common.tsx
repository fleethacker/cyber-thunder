// Small shared building blocks: badges, hashes, code blocks, and the loading/empty/error states.
import { Alert, Badge, Button, Center, Code, CopyButton, Group, Loader, Paper, ScrollArea, Stack, Text, Tooltip } from '@mantine/core';
import {
  IconAlertTriangle, IconBox, IconBrandWindows, IconCloudComputing, IconDeviceDesktop, IconInbox, IconRouter, IconServer,
} from '@tabler/icons-react';
import { useState, type ReactNode } from 'react';
import { catLabel, label, severityColor, short, stateColor, statusColor } from '../lib/format';

export function SeverityBadge({ severity, size = 'md' }: { severity?: string | null; size?: 'xs' | 'sm' | 'md' | 'lg' }) {
  return (
    <Badge color={severityColor(severity)} variant="filled" size={size} radius="sm" style={{ minWidth: 64 }}>
      {catLabel(severity)}
    </Badge>
  );
}

export function StateBadge({ state }: { state?: string | null }) {
  return <Badge color={stateColor(state)} variant="light" radius="sm">{label(state)}</Badge>;
}

export function StatusBadge({ status }: { status?: string | null }) {
  return <Badge color={statusColor(status)} variant="light" radius="sm">{label(status)}</Badge>;
}

export function SimulatedBadge({ simulated }: { simulated?: boolean }) {
  if (!simulated) return null;
  return <Badge color="grape" variant="outline" size="xs" radius="sm">simulated</Badge>;
}

export function AssetIcon({ type, size = 18 }: { type?: string | null; size?: number }) {
  switch (type) {
    case 'linux': return <IconServer size={size} aria-label="linux" />;
    case 'windows': return <IconBrandWindows size={size} aria-label="windows" />;
    case 'cisco_ios': return <IconRouter size={size} aria-label="network device" />;
    case 'kubernetes': return <IconCloudComputing size={size} aria-label="kubernetes" />;
    case 'containers': return <IconBox size={size} aria-label="containers" />;
    default: return <IconDeviceDesktop size={size} aria-label="asset" />;
  }
}

/** Monospace, truncated to 8 with the full value on hover and click-to-copy. */
export function HashText({ value, n = 8 }: { value?: string | null; n?: number }) {
  if (!value) return <Text span ff="monospace">-</Text>;
  return (
    <CopyButton value={value}>
      {({ copied, copy }) => (
        <Tooltip label={copied ? 'copied' : value} withArrow maw={520} multiline>
          <Text span ff="monospace" onClick={copy} style={{ cursor: 'copy' }}>{short(value, n)}</Text>
        </Tooltip>
      )}
    </CopyButton>
  );
}

export function Mono({ children }: { children: ReactNode }) {
  return <Text span ff="monospace" size="sm">{children}</Text>;
}

export function CodeBlock({ code, maxHeight = 320 }: { code: string; maxHeight?: number }) {
  return (
    <ScrollArea.Autosize mah={maxHeight} type="auto">
      <Code block style={{ whiteSpace: 'pre', fontSize: 12 }}>{code}</Code>
    </ScrollArea.Autosize>
  );
}

export function Collapsible({ title, children, initiallyOpen = false }: { title: ReactNode; children: ReactNode; initiallyOpen?: boolean }) {
  const [open, setOpen] = useState(initiallyOpen);
  return (
    <Stack gap={4}>
      <Button variant="subtle" size="compact-sm" onClick={() => setOpen((o) => !o)} style={{ alignSelf: 'flex-start' }}>
        {open ? 'Hide' : 'Show'} {title}
      </Button>
      {open && children}
    </Stack>
  );
}

export function JsonView({ value, maxHeight = 360 }: { value: unknown; maxHeight?: number }) {
  return <CodeBlock code={JSON.stringify(value, null, 2)} maxHeight={maxHeight} />;
}

export function Loading({ what = 'Loading' }: { what?: string }) {
  return (
    <Center py="xl">
      <Group gap="sm"><Loader size="sm" /><Text c="dimmed">{what}...</Text></Group>
    </Center>
  );
}

/** Error box: the API detail verbatim. */
export function ErrorBox({ error, onRetry }: { error: string; onRetry?: () => void }) {
  return (
    <Alert color="red" icon={<IconAlertTriangle size={18} />} title="Request failed">
      <Stack gap="xs">
        <Text size="sm" ff="monospace" style={{ whiteSpace: 'pre-wrap' }}>{error}</Text>
        {onRetry && <Button size="xs" variant="light" color="red" onClick={onRetry} style={{ alignSelf: 'flex-start' }}>Retry</Button>}
      </Stack>
    </Alert>
  );
}

export function Empty({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <Paper withBorder p="xl" radius="md">
      <Stack align="center" gap="sm">
        <IconInbox size={36} opacity={0.5} />
        <Text fw={600} size="lg">{title}</Text>
        {children && <Text c="dimmed" ta="center">{children}</Text>}
        {action}
      </Stack>
    </Paper>
  );
}

/** Standard wrapper: loading on first load, error with retry, empty state, then content. */
export function AsyncView<T>({
  state, empty, isEmpty, children, what,
}: {
  state: { data: T | undefined; error: string | null; loading: boolean; reload: () => Promise<void> };
  empty?: ReactNode;
  isEmpty?: (d: T) => boolean;
  children: (d: T) => ReactNode;
  what?: string;
}) {
  if (state.data === undefined) {
    if (state.error) return <ErrorBox error={state.error} onRetry={() => void state.reload()} />;
    return <Loading what={what} />;
  }
  return (
    <Stack gap="sm">
      {state.error && <ErrorBox error={state.error} onRetry={() => void state.reload()} />}
      {isEmpty && isEmpty(state.data) && empty ? empty : children(state.data)}
    </Stack>
  );
}

export function PageTitle({ title, subtitle, right }: { title: string; subtitle?: string; right?: ReactNode }) {
  return (
    <Group justify="space-between" align="flex-end" mb="md" wrap="wrap">
      <Stack gap={2}>
        <Text component="h1" fz={26} fw={700} m={0}>{title}</Text>
        {subtitle && <Text c="dimmed" size="sm">{subtitle}</Text>}
      </Stack>
      {right && <Group gap="sm">{right}</Group>}
    </Group>
  );
}
