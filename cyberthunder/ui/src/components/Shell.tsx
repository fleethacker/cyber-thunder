// App shell: left nav, header with kill switch and status badges. The header turns red when the
// kill switch is engaged, showing who engaged it and why.
import { ActionIcon, AppShell, Burger, Group, NavLink, ScrollArea, Stack, Text, Tooltip, useMantineColorScheme } from '@mantine/core';
import { useDisclosure } from '@mantine/hooks';
import {
  IconBolt, IconChecklist, IconFileReport, IconHistory, IconListDetails, IconMoon, IconRadar, IconRoute, IconServer2, IconSettings,
  IconStar, IconSun, IconBooks, IconDatabase,
} from '@tabler/icons-react';
import type { ReactNode } from 'react';
import { NavLink as RouterNavLink, useLocation } from 'react-router-dom';
import { fmtTime } from '../lib/format';
import { useAppState } from '../state/AppState';
import { ActorChip } from './ActorChip';
import { ChainBadge, LinkBadge, ModelBadge } from './HeaderBadges';
import { KillSwitch } from './KillSwitch';

const NAV = [
  { to: '/', label: 'Decisions', icon: IconChecklist },
  { to: '/mission', label: 'Mission', icon: IconRoute },
  { to: '/findings', label: 'Findings', icon: IconListDetails },
  { to: '/assets', label: 'Assets', icon: IconServer2 },
  { to: '/scans', label: 'Scans', icon: IconRadar },
  { to: '/content', label: 'STIG Library', icon: IconBooks },
  { to: '/vulnerabilities', label: 'Vulnerability Data', icon: IconDatabase },
  { to: '/audit', label: 'Audit', icon: IconHistory },
  { to: '/reports', label: 'Reports', icon: IconFileReport },
  { to: '/settings', label: 'Settings', icon: IconSettings },
];

function ThemeToggle() {
  const { colorScheme, setColorScheme } = useMantineColorScheme();
  const dark = colorScheme !== 'light';
  return (
    <Tooltip label={dark ? 'Light theme' : 'Dark theme'}>
      <ActionIcon variant="subtle" color="gray" size="lg" onClick={() => setColorScheme(dark ? 'light' : 'dark')} aria-label="Toggle theme">
        {dark ? <IconSun size={18} /> : <IconMoon size={18} />}
      </ActionIcon>
    </Tooltip>
  );
}

export function Shell({ children }: { children: ReactNode }) {
  const [opened, { toggle, close }] = useDisclosure();
  const { status, statusError } = useAppState();
  const loc = useLocation();
  const kill = status?.kill;
  const engaged = !!kill?.engaged;

  return (
    <AppShell
      header={{ height: engaged ? 96 : 64 }}
      navbar={{ width: 220, breakpoint: 'sm', collapsed: { mobile: !opened } }}
      padding="md"
    >
      <AppShell.Header
        style={engaged ? { background: 'var(--mantine-color-red-9)', borderBottomColor: 'var(--mantine-color-red-7)' } : undefined}
      >
        <Stack gap={0} h="100%" justify="center" px="md">
          <Group justify="space-between" wrap="nowrap" gap="sm">
            <Group gap="sm" wrap="nowrap">
              <Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" />
              <IconBolt size={24} color="var(--mantine-color-yellow-5)" />
              <Text fw={800} size="lg" style={{ whiteSpace: 'nowrap' }}>Cyber Thunder</Text>
              {status && <Text size="xs" c="dimmed" visibleFrom="lg">{status.node} · v{status.version}</Text>}
            </Group>
            <Group gap="xs" wrap="nowrap" style={{ overflow: 'hidden' }}>
              <Group gap="xs" wrap="nowrap" visibleFrom="xl">
                <ChainBadge />
                <LinkBadge />
                <ModelBadge />
              </Group>
              <ActorChip />
              <ThemeToggle />
              <KillSwitch />
            </Group>
          </Group>
          {engaged && (
            <Text c="white" fw={700} size="sm" mt={4}>
              KILL SWITCH ENGAGED{kill?.by ? ` by ${kill.by}` : ''}{kill?.at ? ` at ${fmtTime(kill.at)}` : ''}
              {kill?.reason ? `: ${kill.reason}` : ''}{kill?.via && kill.via !== 'state_file' ? ` (${kill.via})` : ''}. All changes are blocked.
            </Text>
          )}
        </Stack>
      </AppShell.Header>

      <AppShell.Navbar p="xs">
        <AppShell.Section grow component={ScrollArea}>
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              component={RouterNavLink}
              to={n.to}
              end={n.to === '/'}
              label={n.label}
              leftSection={<n.icon size={20} />}
              active={n.to === '/' ? loc.pathname === '/' : loc.pathname.startsWith(n.to)}
              onClick={close}
              style={{ borderRadius: 6, minHeight: 44 }}
            />
          ))}
        </AppShell.Section>
        <AppShell.Section>
          <NavLink
            component={RouterNavLink}
            to="/commander"
            label="Commander view"
            leftSection={<IconStar size={20} />}
            active={loc.pathname.startsWith('/commander')}
            onClick={close}
            style={{ borderRadius: 6, minHeight: 44 }}
          />
          <Stack gap={4} hiddenFrom="xl" mt="xs">
            <ChainBadge />
            <LinkBadge />
            <ModelBadge />
          </Stack>
          {statusError && <Text size="xs" c="red" mt="xs" ff="monospace">API: {statusError}</Text>}
        </AppShell.Section>
      </AppShell.Navbar>

      <AppShell.Main>{children}</AppShell.Main>
    </AppShell>
  );
}
