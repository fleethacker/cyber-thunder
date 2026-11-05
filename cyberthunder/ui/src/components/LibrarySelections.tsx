import { Alert, Badge, Button, Checkbox, Drawer, Group, Paper, Radio, Stack, Switch, Table, Text } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useEffect, useState } from 'react';
import { api, ApiError, errorText } from '../api/client';
import type { LibraryKind, LibraryPreferencesInput, LibraryProduct, StigLibrary } from '../api/types';
import { fmtSeconds, fmtZonedTime } from '../lib/format';
import { AvailableTable, DisplayedSelection, HeldTable, KIND_LABELS, LibraryTable, kindLabel } from './LibraryTables';
import { ErrorBox } from './common';

function input(p: LibraryPreferencesInput): LibraryPreferencesInput {
  return { mode: p.mode, products: [...p.products].sort(), kinds: [...p.kinds].sort(), check_on_reconnect: p.check_on_reconnect, auto_pull: p.auto_pull, revision: p.revision };
}

const STATUS: Record<LibraryProduct['status'], { label: string; color: string }> = {
  update_available: { label: 'Update listed', color: 'orange' },
  current: { label: 'Matches index', color: 'teal' },
  not_downloaded: { label: 'Not downloaded', color: 'gray' },
  unavailable: { label: 'Unavailable', color: 'gray' },
};

export function LibrarySelections({ library, disabled, onSaved, onDirtyChange }: {
  library: StigLibrary; disabled: boolean; onSaved: () => Promise<void>; onDirtyChange: (dirty: boolean) => void;
}) {
  const [draft, setDraft] = useState<LibraryPreferencesInput | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [conflict, setConflict] = useState(false);
  const [detailKey, setDetailKey] = useState<string | null>(null);
  const detail = library.products.find((p) => p.product_key === detailKey);
  const prefs = draft ?? input(library.preferences);
  const dirty = !!draft && JSON.stringify(input(draft)) !== JSON.stringify(input(library.preferences));
  // The save response can arrive before the refreshed library carries our new revision.
  const outdated = !saving && (conflict || (!!draft && draft.revision < library.preferences.revision));
  const locked = disabled || saving;
  useEffect(() => onDirtyChange(dirty || saving), [dirty, saving, onDirtyChange]);
  useEffect(() => { if (draft && !dirty && !saving) setDraft(null); }, [draft, dirty, saving]);
  const edit = (change: Partial<LibraryPreferencesInput>) => {
    const next = input({ ...prefs, ...change });
    setDraft(JSON.stringify(next) === JSON.stringify(input(library.preferences)) ? null : next);
  };
  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      const saved = await api.saveLibraryPreferences(input(prefs));
      setDraft(input(saved));
      await onSaved();
      setDraft(null);
      setConflict(false);
      notifications.show({ message: 'Update selections saved. No files downloaded.' });
    } catch (e) {
      setConflict(e instanceof ApiError && e.status === 409);
      setError(errorText(e));
    } finally { setSaving(false); }
  };
  return <Stack gap="md">
    <Paper withBorder p="md" radius="md">
      <Stack gap="md">
        <Group justify="space-between"><Text fw={700}>Choose what this node keeps</Text><Badge color={saving ? 'blue' : dirty ? 'orange' : 'teal'} variant="light">{saving ? 'Saving selections' : dirty ? 'Unsaved changes' : 'Saved selections'}</Badge></Group>
        <Radio.Group label="Product selection" value={prefs.mode} onChange={(value) => edit({ mode: value as LibraryPreferencesInput['mode'] })}>
          <Stack gap="xs" mt="xs">
            <Radio value="inventory" label="Follow inventory recommendations" description="Products are matched to the assets currently in scope." disabled={locked} />
            <Radio value="selected" label="Choose products manually" description="Save a product list, including products without inventory targets." disabled={locked} />
          </Stack>
        </Radio.Group>
        <Checkbox.Group label="Content types" value={prefs.kinds} onChange={(values) => edit({ kinds: values as LibraryKind[] })}>
          <Group mt="xs">{Object.entries(KIND_LABELS).map(([kind, label]) => <Checkbox key={kind} value={kind} label={label} disabled={locked} />)}</Group>
        </Checkbox.Group>
        <Text size="xs" c="dimmed">Manual STIGs and SRGs are guidance. Automated scanning requires a supported SCAP benchmark and scanner.</Text>
        <Switch label="Check for updates when the link reconnects" checked={prefs.check_on_reconnect} disabled={locked}
          onChange={(e) => edit({ check_on_reconnect: e.currentTarget.checked })} />
        <Switch label="Automatically download matching updates on reconnect" checked={prefs.auto_pull} disabled={locked}
          onChange={(e) => edit({ auto_pull: e.currentTarget.checked })} />
        <Text size="xs" c="dimmed">Scheduled check interval: {library.check_interval_s > 0 ? fmtSeconds(library.check_interval_s) : 'disabled'} (server configured). Saving selections never starts a download.</Text>
        {!prefs.kinds.length && <Alert color="yellow">No content types selected. No updates will match.</Alert>}
        {prefs.mode === 'selected' && !prefs.products.length && <Alert color="yellow">Select products below to receive matching updates.</Alert>}
        {outdated && <Alert color="orange" title="Selections changed elsewhere">Your draft has been retained. Load the latest saved selections, then reapply your changes.</Alert>}
        {error && <ErrorBox error={error} />}
        <Group>
          <Button loading={saving} disabled={!dirty || disabled || outdated} onClick={() => void save()}>Save selections</Button>
          <Button variant="default" disabled={saving || (!dirty && !outdated)} onClick={async () => {
            try { await onSaved(); setDraft(null); setConflict(false); setError(null); }
            catch (e) { setError(errorText(e)); }
          }}>
            {outdated ? 'Load saved selections' : 'Discard changes'}
          </Button>
          <Text size="xs" c="dimmed">{library.preferences.updated_at ? `Saved ${fmtZonedTime(library.preferences.updated_at)} by ${library.preferences.updated_by ?? 'unknown'}` : 'Default selections'} · revision {library.preferences.revision}</Text>
        </Group>
      </Stack>
    </Paper>
    <Group justify="space-between">
      <Text fw={700}>Products ({library.products.length})</Text>
      <Button variant="light" disabled={locked} onClick={() => edit({ mode: 'selected', products: library.products.filter((p) => p.recommended).map((p) => p.product_key) })}>Use inventory recommendations</Button>
    </Group>
    <Text size="sm" c="dimmed">{prefs.mode === 'inventory' ? 'Checked products follow inventory recommendations. Choose manual selection to edit the list.' : `${prefs.products.length} products selected across all pages. Save above to persist changes.`} Availability is relative to the {library.catalog.source === 'snapshot' ? 'saved snapshot' : 'last live index'}.</Text>
    <LibraryTable rows={library.products} label="products" empty="The local product index is empty. Refresh the live index when connected."
      searchText={(p) => `${p.title} ${p.product_key} ${p.kinds.map(kindLabel).join(' ')} ${p.targets.join(' ')}`}
      toolbar={(displayed) => prefs.mode === 'selected' && <DisplayedSelection displayed={displayed} selected={prefs.products} keyOf={(p) => p.product_key} onChange={(products) => edit({ products })} disabled={locked} />}
      headings={<><Table.Th>Keep</Table.Th><Table.Th>Product</Table.Th><Table.Th>Content types</Table.Th><Table.Th>Available / held</Table.Th><Table.Th>Index status</Table.Th></>}
      render={(p) => <Table.Tr key={p.product_key}>
        <Table.Td><Checkbox aria-label={`Keep ${p.title}`} disabled={locked || prefs.mode !== 'selected'} checked={prefs.mode === 'inventory' ? p.recommended : prefs.products.includes(p.product_key)}
          onChange={(e) => edit({ products: e.currentTarget.checked ? [...prefs.products, p.product_key] : prefs.products.filter((key) => key !== p.product_key) })} /></Table.Td>
        <Table.Td><Button variant="subtle" p={0} h="auto" justify="flex-start" styles={{ label: { whiteSpace: 'normal', textAlign: 'left' } }} onClick={() => setDetailKey(p.product_key)}>{p.title || p.product_key}</Button>
          <Text size="xs" c="dimmed">{p.product_key}</Text>{p.recommended && <Badge color="blue" variant="light" size="xs">Inventory match</Badge>}</Table.Td>
        <Table.Td>{p.kinds.map((kind) => <Text key={kind} size="xs">{kindLabel(kind)}</Text>)}</Table.Td>
        <Table.Td><Text size="sm">{p.available.length} listed · {p.held.length} local</Text><Text size="xs" c="dimmed">Open product for versions and dates</Text></Table.Td>
        <Table.Td><Badge variant="light" color={STATUS[p.status].color}>{STATUS[p.status].label}</Badge></Table.Td>
      </Table.Tr>} />
    <Drawer opened={!!detail} onClose={() => setDetailKey(null)} title={detail?.title ?? 'Product releases'} size="xl" position="right">
      {detail && <Stack gap="lg">
        <Text size="sm" c="dimmed">{detail.product_key}{detail.targets.length ? ` · Inventory targets: ${detail.targets.join(', ')}` : ' · No inventory targets'}</Text>
        {detail.status === 'unavailable' && <Alert color="yellow">This product is retired, external only, or has no supported download in the local index.</Alert>}
        <Text fw={700}>Available in {library.catalog.source === 'snapshot' ? 'snapshot' : 'last live index'}</Text>
        <AvailableTable rows={detail.available} />
        <Text fw={700}>Held on this node</Text><HeldTable files={detail.held} />
      </Stack>}
    </Drawer>
  </Stack>;
}
