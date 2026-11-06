import { Alert, Badge, Button, Checkbox, Group, Modal, Select, Stack, Text, Textarea, TextInput } from '@mantine/core';
import { useEffect, useRef, useState } from 'react';
import { api, errorText } from '../api/client';
import type { DiscoveryScope, ScopeRangePreview, Target } from '../api/types';
import { scopeRecipesApi } from '../api/scopeRecipes';
import type { ScopeRecipe, ScopeRecipeInput, ScopeRecipePreview, ScopeRecipeRequest, ScopeRecipeSnapshot } from '../api/scopeRecipes';
import { ErrorBox } from './common';
import { useSetupAccess } from './setupAccess';

export function rangeEntries(text: string): string[] {
  // Preserve spaces around a range's hyphen; IP parsing and normalization belong to the server.
  return text.split(/[\n,]+/).map((entry) => entry.replace(/^[ \t\r]+|[ \t\r]+$/g, '')).filter(Boolean);
}

export function ScopePreviewView({ preview }: { preview: ScopeRangePreview }) {
  return <Stack gap="xs">
    <Group gap="xs"><Badge color={preview.can_save && !preview.truncated ? 'blue' : 'orange'}>
      {preview.can_save && !preview.truncated ? 'Ready for explicit range confirmation' : 'Range save blocked'}
    </Badge><Text size="sm">{preview.network_count} normalized networks</Text></Group>
    <Text size="sm">Included address count: {preview.input_address_count} · removed by exclusions: {preview.excluded_address_count} · effective address count: {preview.address_count}</Text>
    <Text size="sm" c="dimmed">Counts include network and broadcast addresses. They are address-space counts, not discovered hosts or authorized inventory assets.</Text>
    {preview.blocking_reasons.map((message, i) => <Alert color="red" key={i}>{message}</Alert>)}
    {typeof preview.requires_normalization_acknowledgment !== 'boolean' || !Array.isArray(preview.normalizations)
      ? <Alert color="orange">Normalization details are unavailable. An updated preview is required before saving.</Alert>
      : preview.normalizations.map((item, i) => <Alert color="orange" title="CIDR broadening requires acknowledgement" key={i}>
        {item.recipe_name ? `${item.recipe_name} · ` : ''}{item.field === 'exclude' ? 'Exclusion' : 'Inclusion'}: {item.input} expands to {item.normalized}. Review the whole network, including addresses below the supplied host address.
      </Alert>)}
    {preview.warnings.map((message, i) => <Alert color="orange" title="Range normalization or coverage warning" key={i}>{message}</Alert>)}
    {preview.truncated && <Alert color="orange">The preview is truncated. Saving is disabled; narrow the inputs and preview again.</Alert>}
    <Text fw={600} size="sm">Exact effective search ranges</Text>
    {preview.networks.length ? <Text size="sm" ff="monospace" style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxHeight: 220, overflow: 'auto' }}>{preview.networks.join('\n')}</Text>
      : <Alert color="orange">No effective search ranges. A permitted empty save clears the saved discovery ranges.</Alert>}
    <Text size="sm" c="dimmed">Save limits: {preview.limits.max_entries} input entries, {preview.limits.max_networks} networks and {preview.limits.max_addresses} effective addresses.</Text>
  </Stack>;
}

type DraftRecipe = ScopeRecipeInput & { includeText: string; excludeText: string; networks: string[] };
const draftOf = (r: ScopeRecipe): DraftRecipe => ({ ...r, includeText: r.include?.join('\n') ?? '', excludeText: r.exclude?.join('\n') ?? '' });
const emptyRecipe = (id: string): DraftRecipe => ({ id, name: 'New recipe', include: [], exclude: [], includeText: '', excludeText: '',
  allow_public: false, scanner_target: null, acknowledge_normalization: false, networks: [] });
const recipeInput = (r: DraftRecipe): ScopeRecipeInput => ({ id: r.id, name: r.name,
  include: r.include === null || r.includeText === r.include.join('\n') ? r.include : rangeEntries(r.includeText),
  exclude: r.exclude === null || r.excludeText === r.exclude.join('\n') ? r.exclude : rangeEntries(r.excludeText), allow_public: r.allow_public,
  scanner_target: r.scanner_target, acknowledge_normalization: r.acknowledge_normalization });

export function ScopeEditorContent({ current, onSaved, onClose, setBusy }: {
  current: DiscoveryScope[]; onSaved: () => void; onClose: () => void; setBusy: (value: boolean) => void;
}) {
  const blocked = useSetupAccess();
  const alive = useRef(true);
  const requestId = useRef(0);
  const loadId = useRef(0);
  const inFlight = useRef(false);
  const baseline = useRef(JSON.stringify(current));
  const newId = useRef(0);
  const reviewed = useRef<{ body: ScopeRecipeRequest; fingerprint: string }>();
  const [snapshot, setSnapshot] = useState<ScopeRecipeSnapshot>();
  const [drafts, setDrafts] = useState<DraftRecipe[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [reason, setReason] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [warningsAccepted, setWarningsAccepted] = useState(false);
  const [result, setResult] = useState<ScopeRecipePreview>();
  const [loading, setLoading] = useState(true);
  const [previewing, setPreviewing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [conflict, setConflict] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [targetsError, setTargetsError] = useState<string | null>(null);
  const preview = result?.preview;
  const selectedRecipe = drafts.find((r) => r.id === selected);
  const changedElsewhere = baseline.current !== JSON.stringify(current) || conflict;
  const working = loading || previewing || saving;
  const inputs = (): ScopeRecipeRequest => ({ revision: snapshot?.revision ?? '', recipes: drafts.map(recipeInput) });
  const entries = drafts.flatMap((r) => r.include === null ? r.networks : [...rangeEntries(r.includeText), ...rangeEntries(r.excludeText)]);
  const inputProblem = entries.length > 128 ? 'Use at most 128 include and exclude entries across all recipes.'
    : entries.some((entry) => entry.length > 256) ? 'Each address, CIDR or range must be at most 256 characters.'
    : drafts.some((r) => !r.name.trim() || r.name.length > 80) ? 'Every recipe needs a name of at most 80 characters.' : null;
  const invalidate = () => {
    requestId.current++; reviewed.current = undefined; setResult(undefined); setConfirmed(false); setWarningsAccepted(false); setError(null);
  };
  const restore = (value: ScopeRecipeSnapshot) => {
    const rows = value.recipes.length ? value.recipes.map(draftOf) : [emptyRecipe('range-new')];
    setDrafts(rows); setSelected(rows[0]?.id ?? null); setReason(''); invalidate();
  };
  const reload = async () => {
    if (inFlight.current) return;
    inFlight.current = true; setLoading(true); setLoadError(null); invalidate();
    const loadTicket = ++loadId.current;
    const ticket = requestId.current;
    // Bind to the props at request time; a parent update during loading still requires review.
    const currentAtLoad = JSON.stringify(current);
    try {
      const value = await scopeRecipesApi.load();
      if (alive.current && ticket === requestId.current) {
        setSnapshot(value); baseline.current = currentAtLoad; setConflict(false); restore(value);
      }
    } catch (e) { if (alive.current && ticket === requestId.current) setLoadError(errorText(e)); }
    finally {
      if (loadTicket === loadId.current) { inFlight.current = false; if (alive.current) setLoading(false); }
    }
  };
  useEffect(() => {
    alive.current = true;
    void reload();
    let active = true;
    void api.targets().then((value) => { if (active) setTargets(value.targets); })
      .catch((e) => { if (active) setTargetsError(errorText(e)); });
    return () => { active = false; alive.current = false; requestId.current++; loadId.current++; inFlight.current = false; };
  }, []);
  const edit = (changes: Partial<DraftRecipe>) => {
    if (working) return;
    setDrafts((rows) => rows.map((r) => r.id === selected ? { ...r, ...changes, acknowledge_normalization: false } : r));
    invalidate();
  };
  const showPreview = async () => {
    if (inFlight.current || loading || loadError || !snapshot || inputProblem || changedElsewhere) return;
    inFlight.current = true;
    const ticket = ++requestId.current;
    const body = inputs();
    reviewed.current = undefined; setResult(undefined); setPreviewing(true); setConfirmed(false); setWarningsAccepted(false); setError(null);
    try {
      const value = await scopeRecipesApi.preview(body);
      if (alive.current && ticket === requestId.current) {
        setResult(value);
        if (value.revision === body.revision && typeof value.fingerprint === 'string') reviewed.current = { body, fingerprint: value.fingerprint };
      }
    } catch (e) {
      if (alive.current && ticket === requestId.current) { setError(errorText(e)); if ((e as { status?: number }).status === 409) setConflict(true); }
    } finally { inFlight.current = false; if (alive.current) setPreviewing(false); }
  };
  const normalizationKnown = !!preview && typeof preview.requires_normalization_acknowledgment === 'boolean' && Array.isArray(preview.normalizations);
  const needsNormalizationAck = preview?.requires_normalization_acknowledgment === true || (preview?.normalizations?.length ?? 0) > 0;
  const normalizationAccepted = !!result && result.recipes.every((row) => !row.preview.requires_normalization_acknowledgment ||
    drafts.find((r) => r.id === row.id)?.acknowledge_normalization === true);
  const bound = !!reviewed.current && JSON.stringify(reviewed.current.body) === JSON.stringify(inputs());
  const canSave = !!preview && normalizationKnown && bound && (!needsNormalizationAck || normalizationAccepted) &&
    preview.can_save === true && preview.truncated === false && preview.blocking_reasons.length === 0 &&
    confirmed && (preview.warnings.length === 0 || warningsAccepted) && !!reason.trim() && reason.trim().length <= 1000 &&
    !blocked && !inputProblem && !changedElsewhere && !working && !loadError;
  const save = async () => {
    if (!canSave || inFlight.current || !reviewed.current) return;
    inFlight.current = true; setSaving(true); setBusy(true); setError(null);
    const { body, fingerprint } = reviewed.current;
    try {
      await scopeRecipesApi.save({ ...body, preview_fingerprint: fingerprint, reason: reason.trim() });
      if (alive.current) { onSaved(); onClose(); }
    } catch (e) {
      if (alive.current) {
        setError(errorText(e)); reviewed.current = undefined; setConfirmed(false);
        if ((e as { status?: number }).status === 409) setConflict(true);
      }
    } finally { inFlight.current = false; if (alive.current) setSaving(false); setBusy(false); }
  };
  const scanner = selectedRecipe?.scanner_target ?? '';
  const scannerChoices = [{ value: '', label: 'This service environment' }, ...targets.filter((target) => target.in_scope).map((target) => ({ value: target.id, label: `${target.name} (${target.id})` }))];
  if (scanner && !scannerChoices.some((choice) => choice.value === scanner)) scannerChoices.push({ value: scanner, label: `${scanner} (existing declaration; eligibility unverified)` });

  return <Stack gap="sm">
    <Alert color="blue">Discovery search ranges limit where a separately requested sweep may look. Saving them does not authorize inventory assets, accept candidates or start a sweep or scan.</Alert>
    <Text size="sm">Recipes retain their own include/exclude expressions, public-address policy and scanner. Exclusions apply only within their recipe. Enter one IPv4/IPv6 address, CIDR, or inclusive start-end range per line (or separated by commas). No DNS names.</Text>
    {changedElsewhere && <Alert color="orange">Saved search recipes changed while this editor was open. Reload saved recipes and review a fresh preview before saving.</Alert>}
    {loadError && <ErrorBox error={loadError} />}
    <Group>
      <Button type="button" variant="default" disabled={working} onClick={() => void reload()}>Reload saved recipes</Button>
      <Button type="button" variant="default" disabled={working || !snapshot} onClick={() => { if (!inFlight.current && snapshot) restore(snapshot); }}>Reset unsaved edits</Button>
    </Group>
    {loading && <Text role="status">Loading saved recipes…</Text>}
    <fieldset disabled={working || !snapshot || !!loadError} style={{ border: 0, padding: 0, margin: 0 }}>
      <Stack gap="sm">
        <Select label="Recipe to edit" data={drafts.map((r) => ({ value: r.id, label: r.name || 'Unnamed recipe' }))}
          value={selected} allowDeselect={false} onChange={setSelected} />
        <Group>
          <Button type="button" variant="light" onClick={() => {
            if (working) return;
            let id: string;
            do { id = `range-new-${++newId.current}`; } while (drafts.some((r) => r.id === id));
            setDrafts((rows) => [...rows, emptyRecipe(id)]); setSelected(id); invalidate();
          }}>Add recipe</Button>
          <Button type="button" variant="default" disabled={!selectedRecipe} onClick={() => {
            if (working) return;
            const rows = drafts.filter((r) => r.id !== selected); setDrafts(rows); setSelected(rows[0]?.id ?? null); invalidate();
          }}>Remove selected recipe</Button>
        </Group>
        {selectedRecipe && <>
          <TextInput label="Recipe name" maxLength={80} value={selectedRecipe.name} onChange={(e) => edit({ name: e.currentTarget.value })} />
          {selectedRecipe.include === null ? <Alert color="orange">
            <Text>Legacy effective ranges only. Original include/exclude expressions are unknown and have not been reconstructed.</Text>
            <Text ff="monospace">{selectedRecipe.networks.join(', ')}</Text>
            <Text>Scanner: {scanner || 'This service environment'} · Public addresses: {selectedRecipe.allow_public ? 'permitted' : 'not permitted'}</Text>
            <Button type="button" mt="xs" variant="light" onClick={() => edit({ include: selectedRecipe.networks, exclude: [],
              includeText: selectedRecipe.networks.join('\n'), excludeText: '' })}>Use effective ranges as new expressions</Button>
          </Alert> : <>
            <Textarea label="Search addresses or ranges" value={selectedRecipe.includeText} autosize minRows={3} maxRows={8} ff="monospace"
              placeholder={'10.20.30.40\n10.20.30.50-10.20.30.60\nfd00::1/128'} onChange={(e) => edit({ includeText: e.currentTarget.value })} />
            <Textarea label="Exclude addresses or ranges" value={selectedRecipe.excludeText} autosize minRows={2} maxRows={6} ff="monospace"
              description="Excluded addresses are removed from this recipe only. Inventory authorization is unchanged."
              onChange={(e) => edit({ excludeText: e.currentTarget.value })} />
            <Select label="Scanner vantage point" description="An authorized inventory scanner, or this service environment. In a container this is its network view, not the physical host."
              data={scannerChoices} value={scanner} allowDeselect={false} onChange={(value) => edit({ scanner_target: value || null })} />
            <Checkbox label="Allow public address space in this reviewed selection" checked={selectedRecipe.allow_public} onChange={(e) => edit({ allow_public: e.currentTarget.checked })} />
          </>}
        </>}
        {!drafts.length && <Alert color="orange">All recipes are removed in this draft. Preview and confirm to clear saved discovery ranges.</Alert>}
        {targetsError && <Alert color="orange">Scanner inventory could not be refreshed: {targetsError}. Existing declarations are retained; the server rechecks scanner authorization on save.</Alert>}
      </Stack>
    </fieldset>
    {inputProblem && <Alert color="orange">{inputProblem}</Alert>}
    <Button type="button" variant="light" disabled={!!inputProblem || changedElsewhere || working || !snapshot || !!loadError} loading={previewing} onClick={() => void showPreview()}>Preview exact search ranges</Button>
    {preview && <ScopePreviewView preview={preview} />}
    {result && result.recipes.map((row) => {
      const r = drafts.find((recipe) => recipe.id === row.id);
      return <Stack key={row.id} gap={2}>
        <Text size="sm">{row.name}: {row.preview.address_count} addresses · scanner {r?.scanner_target || 'This service environment'} · public addresses {r?.allow_public ? 'permitted' : 'not permitted'}</Text>
        <Text size="sm" ff="monospace" style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxHeight: 120, overflow: 'auto' }}>{row.preview.networks.join('\n') || 'No effective ranges'}</Text>
      </Stack>;
    })}
    {preview && <>
      {needsNormalizationAck && <>
        <Checkbox disabled={saving || previewing} label="I acknowledge the listed CIDR broadening for these exact inputs" checked={normalizationAccepted}
          onChange={(e) => {
            const accepted = e.currentTarget.checked;
            const ids = new Set(result?.recipes.filter((r) => r.preview.requires_normalization_acknowledgment).map((r) => r.id));
            setDrafts((rows) => rows.map((r) => ids.has(r.id) ? { ...r, acknowledge_normalization: accepted } : r));
            setConfirmed(false); setWarningsAccepted(false);
          }} />
        {!bound && <Text size="sm">Preview again with this acknowledgement before confirming the search ranges.</Text>}
      </>}
      <Textarea label="Search range decision reason" required maxLength={1000} disabled={saving} value={reason}
        description="Required for the audited search-range decision; this is not inventory authorization."
        onChange={(e) => { setReason(e.currentTarget.value); setConfirmed(false); }} />
      {preview.warnings.length > 0 && <Checkbox disabled={saving} label="I acknowledge the additional range warnings" checked={warningsAccepted} onChange={(e) => setWarningsAccepted(e.currentTarget.checked)} />}
      <Checkbox disabled={saving} label="I reviewed the exact effective search ranges and exclusions; inventory authorization stays unchanged" checked={confirmed} onChange={(e) => setConfirmed(e.currentTarget.checked)} />
    </>}
    {blocked && <Alert color="yellow">{blocked}</Alert>}
    {error && <ErrorBox error={error} />}
    <Group justify="flex-end">
      <Button type="button" variant="default" disabled={saving} onClick={() => { if (!inFlight.current || !saving) onClose(); }}>Cancel</Button>
      <Button type="button" disabled={!canSave || saving} loading={saving} onClick={() => void save()}>Confirm search ranges</Button>
    </Group>
  </Stack>;
}

export function ScopeEditor({ opened, current, onClose, onSaved }: {
  opened: boolean; current: DiscoveryScope[]; onClose: () => void; onSaved: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const inFlight = useRef(false);
  return <Modal opened={opened} title="Edit discovery search ranges" size="lg" centered
    onClose={() => { if (!inFlight.current) onClose(); }} closeOnClickOutside={!busy} closeOnEscape={!busy} withCloseButton={!busy}>
    {opened && <ScopeEditorContent current={current} onClose={onClose} onSaved={onSaved} setBusy={(value) => { inFlight.current = value; setBusy(value); }} />}
  </Modal>;
}
