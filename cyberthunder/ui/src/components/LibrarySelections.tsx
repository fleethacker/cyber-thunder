import { Alert, Badge, Button, Checkbox, Drawer, Group, Paper, Radio, Select, Stack, Switch, Table, Text } from '@mantine/core';
import { notifications } from '@mantine/notifications';
import { useEffect, useState } from 'react';
import { api, ApiError, errorText } from '../api/client';
import type { LibraryKind, LibraryPreferencesInput, LibraryProduct, StigLibrary } from '../api/types';
import { fmtSeconds, fmtZonedTime } from '../lib/format';
import { isMaintained, productSearch } from '../lib/contentTasks';
import { AvailableTable, DisplayedSelection, HeldTable, KIND_LABELS, LibraryTable, kindLabel } from './LibraryTables';
import { ErrorBox } from './common';

function input(p: LibraryPreferencesInput): LibraryPreferencesInput {
  return { mode: p.mode, products: [...p.products].sort(), kinds: [...p.kinds].sort(), check_on_reconnect: p.check_on_reconnect, auto_pull: p.auto_pull, revision: p.revision };
}

const STATUS: Record<LibraryProduct['status'], { label: string; color: string }> = {
  update_available: { label: 'Update listed', color: 'orange' },
  current: { label: 'Matches saved catalog', color: 'teal' },
  not_downloaded: { label: 'Not downloaded', color: 'gray' },
  unavailable: { label: 'Unavailable', color: 'gray' },
};

export function LibrarySelections({ library, disabled, onSaved, onDirtyChange, view = 'maintained', productKey, onProductChange, onBrowse }: {
  library: StigLibrary; disabled: boolean; onSaved: () => Promise<void>; onDirtyChange: (dirty: boolean) => void;
  view?: 'maintained' | 'browse'; productKey?: string | null; onProductChange?: (key: string | null) => void; onBrowse?: () => void;
}) {
  const [draft, setDraft] = useState<LibraryPreferencesInput | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [conflict, setConflict] = useState(false);
  const [localDetailKey, setLocalDetailKey] = useState<string | null>(null);
  const detailKey = productKey === undefined ? localDetailKey : productKey;
  const setDetailKey = onProductChange ?? setLocalDetailKey;
  const [kind, setKind] = useState<string | null>(null);
  const [availability, setAvailability] = useState<string | null>(null);
  const [maintenance, setMaintenance] = useState<string | null>(null);
  const detail = library.products.find((p) => p.product_key === detailKey);
  const prefs = draft ?? input(library.preferences);
  const dirty = !!draft && JSON.stringify(input(draft)) !== JSON.stringify(input(library.preferences));
  // The save response can arrive before the refreshed library carries our new revision.
  const outdated = !saving && (conflict || (!!draft && draft.revision < library.preferences.revision));
  const locked = disabled || saving;
  const savedCount = library.products.filter((p) => isMaintained(p, library.preferences)).length;
  const draftCount = library.products.filter((p) => isMaintained(p, prefs)).length;
  const products = library.products.filter((p) =>
    (view === 'browse' || isMaintained(p, prefs) || isMaintained(p, library.preferences))
    && (!kind || p.kinds.includes(kind))
    && (!availability || p.status === availability)
    && (view !== 'browse' || !maintenance || isMaintained(p, library.preferences) === (maintenance === 'maintained')));
  useEffect(() => onDirtyChange(dirty || saving), [dirty, saving, onDirtyChange]);
  useEffect(() => { if (draft && !dirty && !saving) setDraft(null); }, [draft, dirty, saving]);
  const edit = (change: Partial<LibraryPreferencesInput>) => {
    if (locked) return;
    const next = input({ ...prefs, ...change });
    setDraft(JSON.stringify(next) === JSON.stringify(input(library.preferences)) ? null : next);
  };
  const save = async () => {
    if (!dirty || locked || outdated) return;
    setSaving(true);
    setError(null);
    try {
      const saved = await api.saveLibraryPreferences(input(prefs));
      setDraft(input(saved));
      await onSaved();
      setDraft(null);
      setConflict(false);
      notifications.show({ message: 'Maintenance selections saved. No files downloaded.' });
    } catch (e) {
      setConflict(e instanceof ApiError && e.status === 409);
      setError(errorText(e));
    } finally { setSaving(false); }
  };
  return <Stack gap="md">
    <Paper withBorder p="md" radius="md">
      <Stack gap="md">
        <Group justify="space-between"><Text fw={700}>{view === 'maintained' ? 'Products selected for maintenance' : 'Browse the saved product catalog'}</Text><Badge color={saving ? 'blue' : dirty ? 'orange' : 'teal'} variant="light">{saving ? 'Saving selections' : dirty ? 'Unsaved changes' : 'Saved selections'}</Badge></Group>
        <Text size="sm">{savedCount} products in saved selections{dirty ? ` · ${draftCount} in your draft` : ''}. Selection controls matching updates; it does not mean content is downloaded or configured for scanning.</Text>
        {view === 'maintained' && <>
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
        </>}
        {view === 'browse' && <Group>
          <Text size="sm">Content types: {prefs.kinds.map(kindLabel).join(', ') || 'none'}. Change types and reconnect options in Maintained.</Text>
          {prefs.mode === 'inventory' && <Button variant="light" disabled={locked}
            onClick={() => edit({ mode: 'selected', products: library.products.filter((p) => p.recommended).map((p) => p.product_key) })}>Choose products manually</Button>}
        </Group>}
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
      <Text fw={700}>{view === 'browse' ? 'All catalog products' : 'Maintenance selections'} ({products.length})</Text>
      <Button variant="light" disabled={locked} onClick={() => edit({ mode: 'selected', products: library.products.filter((p) => p.recommended).map((p) => p.product_key) })}>Use inventory recommendations</Button>
    </Group>
    {view === 'browse' ? <Text size="sm" c="dimmed">Search every product returned by this node's saved catalog, including products outside inventory. The catalog covers recognized Manual STIG, SRG and SCAP entries; it is not a guarantee of every cyber.mil publication. To download a product, select it for maintenance, save, then open Updates.</Text>
      : <Group><Text size="sm" c="dimmed">Saved choices and pending additions or removals are shown together. Find other products in Browse all.</Text>{onBrowse && <Button variant="light" onClick={onBrowse}>Browse all products</Button>}</Group>}
    <Text size="sm" c="dimmed">{prefs.mode === 'inventory' ? 'Checked products follow inventory recommendations. Choose manual selection to edit the list.' : `${prefs.products.length} products selected across all pages. Save above to persist changes.`} Availability is relative to the {library.catalog.source === 'snapshot' ? 'saved snapshot' : 'last live index'}.</Text>
    <Group align="flex-end">
      <Select label="Content type" placeholder="All types" clearable data={Object.entries(KIND_LABELS).map(([value, label]) => ({ value, label }))} value={kind} onChange={setKind} />
      <Select label="Catalog comparison" placeholder="All statuses" clearable data={Object.entries(STATUS).map(([value, item]) => ({ value, label: item.label }))} value={availability} onChange={setAvailability} />
      {view === 'browse' && <Select label="Saved maintenance" placeholder="All products" clearable data={[{ value: 'maintained', label: 'Selected for maintenance' }, { value: 'other', label: 'Not selected' }]} value={maintenance} onChange={setMaintenance} />}
      <Button variant="subtle" onClick={() => { setKind(null); setAvailability(null); setMaintenance(null); }}>Clear product filters</Button>
    </Group>
    <LibraryTable rows={products} label="products" empty={view === 'browse' ? 'No products match. Clear filters or check cyber.mil when connected.' : 'No maintenance selections match. Browse all to choose products.'}
      searchText={productSearch}
      toolbar={(displayed) => prefs.mode === 'selected' && <DisplayedSelection displayed={displayed} selected={prefs.products} keyOf={(p) => p.product_key} onChange={(products) => edit({ products })} disabled={locked} />}
      headings={<><Table.Th>Maintain</Table.Th><Table.Th>Product / saved choice</Table.Th><Table.Th>Listed versions</Table.Th><Table.Th>Local versions</Table.Th><Table.Th>Catalog comparison</Table.Th></>}
      render={(p) => <Table.Tr key={p.product_key}>
        <Table.Td><Checkbox aria-label={`Maintain ${p.title}`} disabled={locked || prefs.mode !== 'selected'} checked={isMaintained(p, prefs)}
          onChange={(e) => edit({ products: e.currentTarget.checked ? [...prefs.products, p.product_key] : prefs.products.filter((key) => key !== p.product_key) })} /></Table.Td>
        <Table.Td><Button variant="subtle" p={0} h="auto" justify="flex-start" styles={{ label: { whiteSpace: 'normal', textAlign: 'left' } }} onClick={() => setDetailKey(p.product_key)}>{p.title || p.product_key}</Button>
          <Text size="xs" c="dimmed">{p.product_key}</Text>
          <Text size="xs">{isMaintained(p, library.preferences) ? 'Saved: maintained' : 'Saved: not maintained'}</Text>
          {isMaintained(p, prefs) !== isMaintained(p, library.preferences) && <Badge color="orange" variant="light" size="xs">{isMaintained(p, prefs) ? 'Draft: add' : 'Draft: remove'}</Badge>}
          {p.recommended && <Badge color="blue" variant="light" size="xs">Inventory match</Badge>}</Table.Td>
        <Table.Td>{p.kinds.map((kind) => {
          const release = p.available.find((r) => r.kind === kind && !r.sunset && r.allowed !== false) ?? p.available.find((r) => r.kind === kind);
          return <Text key={kind} size="xs">{kindLabel(kind)}: {release?.version_label || 'Version not provided'}</Text>;
        })}{!p.kinds.length && <Text size="xs">No release listed</Text>}</Table.Td>
        <Table.Td>{p.held.length ? [...new Set(p.held.map((file) => `${kindLabel(file.kind)}: ${file.version_label || file.benchmark_release || 'Version not provided'}`))].map((version) => <Text size="xs" key={version}>{version}</Text>) : <Text size="sm" c="dimmed">Not downloaded</Text>}
          <Text size="xs" c="dimmed">{p.held.length} local file(s) · open product for dates</Text></Table.Td>
        <Table.Td><Badge variant="light" color={STATUS[p.status].color}>{STATUS[p.status].label}</Badge></Table.Td>
      </Table.Tr>} />
    <Drawer opened={!!detailKey} onClose={() => setDetailKey(null)} title={detail?.title ?? 'Product releases'} size="xl" position="right">
      {!detail && <Alert color="yellow">Product {detailKey} is not in this node's saved catalog. Close this panel to search Browse all or check cyber.mil when connected.</Alert>}
      {detail && <Stack gap="lg">
        <Text size="sm" c="dimmed">{detail.product_key}{detail.targets.length ? ` · Inventory targets: ${detail.targets.join(', ')}` : ' · No inventory targets'}</Text>
        <Text size="sm">{isMaintained(detail, library.preferences) ? 'Selected for maintenance in saved settings.' : 'Not selected for maintenance in saved settings.'} {detail.held.length} local file(s).</Text>
        <Alert color="blue" title="Content is not scanner coverage">Manual STIGs and SRGs are rules and guidance. SCAP content needs a compatible scanner, configuration and deployment for the target. This library does not verify those conditions.</Alert>
        {detail.status === 'unavailable' && <Alert color="yellow">This product is retired, external only, or has no supported download in the local index.</Alert>}
        <Text fw={700}>Available in {library.catalog.source === 'snapshot' ? 'snapshot' : 'last live index'}</Text>
        <AvailableTable rows={detail.available} />
        <Text fw={700}>Downloaded or imported on this node</Text><HeldTable files={detail.held} />
      </Stack>}
    </Drawer>
  </Stack>;
}
