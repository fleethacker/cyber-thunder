import { Alert, Badge, Button, Checkbox, Group, Modal, Select, Stack, Text, Textarea } from '@mantine/core';
import { useEffect, useRef, useState } from 'react';
import { api, errorText } from '../api/client';
import type { DiscoveryScope, ScopeRangeInput, ScopeRangePreview, Target } from '../api/types';
import { ErrorBox } from './common';
import { useSetupAccess } from './setupAccess';

export function rangeEntries(text: string): string[] {
  // Preserve spaces around a range's hyphen; IP parsing and normalization belong to the server.
  return text.split(/[\n,]+/).map((entry) => entry.trim()).filter(Boolean);
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
        {item.field === 'exclude' ? 'Exclusion' : 'Inclusion'}: {item.input} expands to {item.normalized}. Review the whole network, including addresses below the supplied host address.
      </Alert>)}
    {preview.warnings.map((message, i) => <Alert color="orange" title="Range normalization or coverage warning" key={i}>{message}</Alert>)}
    {preview.truncated && <Alert color="orange">The preview is truncated. Saving is disabled; narrow the inputs and preview again.</Alert>}
    <Text fw={600} size="sm">Exact effective search ranges</Text>
    {preview.networks.length ? <Text size="sm" ff="monospace" style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxHeight: 220, overflow: 'auto' }}>{preview.networks.join('\n')}</Text>
      : <Alert color="orange">No effective search ranges. A permitted empty save clears the saved discovery ranges.</Alert>}
    <Text size="sm" c="dimmed">Save limits: {preview.limits.max_entries} input entries, {preview.limits.max_networks} networks and {preview.limits.max_addresses} effective addresses.</Text>
  </Stack>;
}

export function ScopeEditorContent({ current, onSaved, onClose, setBusy }: {
  current: DiscoveryScope[]; onSaved: () => void; onClose: () => void; setBusy: (value: boolean) => void;
}) {
  const blocked = useSetupAccess();
  const alive = useRef(true);
  const requestId = useRef(0);
  const inFlight = useRef(false);
  const baseline = useRef(JSON.stringify(current));
  const policies = useRef(new Set(current.map((scope) => JSON.stringify([scope.allow_public, scope.scanner_target]))));
  const mixed = policies.current.size > 1;
  const [include, setInclude] = useState(() => current.map((scope) => scope.cidr).join('\n'));
  const [exclude, setExclude] = useState('');
  const [allowPublic, setAllowPublic] = useState(() => current.length > 0 && current.every((scope) => scope.allow_public));
  const [scanner, setScanner] = useState(() => mixed ? '' : current[0]?.scanner_target ?? '');
  const [replacePolicies, setReplacePolicies] = useState(false);
  const [reason, setReason] = useState('');
  const [confirmed, setConfirmed] = useState(false);
  const [warningsAccepted, setWarningsAccepted] = useState(false);
  const [normalizationAccepted, setNormalizationAccepted] = useState(false);
  const [previewAcknowledgement, setPreviewAcknowledgement] = useState(false);
  const [preview, setPreview] = useState<ScopeRangePreview>();
  const [previewing, setPreviewing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [targetsError, setTargetsError] = useState<string | null>(null);

  useEffect(() => {
    alive.current = true;
    let active = true;
    void api.targets().then((value) => { if (active) setTargets(value.targets); })
      .catch((e) => { if (active) setTargetsError(errorText(e)); });
    return () => { active = false; alive.current = false; requestId.current++; };
  }, []);
  const changedElsewhere = baseline.current !== JSON.stringify(current);
  const inputs = (): ScopeRangeInput => ({ include: rangeEntries(include), exclude: rangeEntries(exclude), allow_public: allowPublic, scanner_target: scanner || null, acknowledge_normalization: normalizationAccepted });
  const entries = [...rangeEntries(include), ...rangeEntries(exclude)];
  const inputProblem = entries.length > 128 ? 'Use at most 128 include and exclude entries combined.'
    : entries.some((entry) => entry.length > 256) ? 'Each address, CIDR or range must be at most 256 characters.' : null;
  const invalidate = () => { requestId.current++; setPreview(undefined); setConfirmed(false); setWarningsAccepted(false); setNormalizationAccepted(false); setPreviewAcknowledgement(false); setError(null); };
  const showPreview = async () => {
    if (inFlight.current || inputProblem || changedElsewhere) return;
    inFlight.current = true;
    const ticket = ++requestId.current;
    setPreview(undefined); setPreviewing(true); setConfirmed(false); setWarningsAccepted(false); setError(null);
    try {
      const value = await api.previewScopeRanges(inputs());
      if (alive.current && ticket === requestId.current) { setPreview(value); setPreviewAcknowledgement(normalizationAccepted); }
    } catch (e) { if (alive.current && ticket === requestId.current) setError(errorText(e)); }
    finally { inFlight.current = false; if (alive.current) setPreviewing(false); }
  };
  const normalizationKnown = !!preview && typeof preview.requires_normalization_acknowledgment === 'boolean' && Array.isArray(preview.normalizations);
  const needsNormalizationAck = preview?.requires_normalization_acknowledgment === true || (preview?.normalizations?.length ?? 0) > 0;
  const canSave = !!preview && normalizationKnown && previewAcknowledgement === normalizationAccepted && (!needsNormalizationAck || normalizationAccepted) &&
    preview.can_save === true && preview.truncated === false && preview.blocking_reasons.length === 0 &&
    confirmed && (preview.warnings.length === 0 || warningsAccepted) && !!reason.trim() && reason.trim().length <= 1000 &&
    (!mixed || replacePolicies) && !blocked && !inputProblem && !changedElsewhere && !previewing;
  const save = async () => {
    if (!canSave || inFlight.current) return;
    inFlight.current = true; setSaving(true); setBusy(true); setError(null);
    try {
      await api.saveScopeRanges({ ...inputs(), reason: reason.trim() });
      if (alive.current) { onSaved(); onClose(); }
    } catch (e) { if (alive.current) setError(errorText(e)); }
    finally { inFlight.current = false; if (alive.current) { setSaving(false); setBusy(false); } }
  };
  const scannerChoices = [{ value: '', label: 'This service environment' }, ...targets.filter((target) => target.in_scope).map((target) => ({ value: target.id, label: `${target.name} (${target.id})` }))];
  if (scanner && !scannerChoices.some((choice) => choice.value === scanner)) scannerChoices.push({ value: scanner, label: `${scanner} (existing declaration; eligibility unverified)` });

  return <Stack gap="sm">
    <Alert color="blue">Discovery search ranges limit where a separately requested sweep may look. Saving them does not authorize inventory assets, accept candidates or start a sweep or scan.</Alert>
    <Text size="sm">Enter one IPv4/IPv6 address, CIDR, or inclusive start-end range per line (or separated by commas). No DNS names. A CIDR with host bits can broaden to its whole network; review the exact normalized output.</Text>
    {changedElsewhere && <Alert color="orange">Saved search ranges changed while this editor was open. Close and reopen it before saving.</Alert>}
    <fieldset disabled={previewing || saving} style={{ border: 0, padding: 0, margin: 0 }}>
      <Stack gap="sm">
        <Textarea label="Search addresses or ranges" value={include} autosize minRows={3} maxRows={8} ff="monospace"
          placeholder={'10.20.30.40\n10.20.30.50-10.20.30.60\nfd00::1/128'} onChange={(e) => { setInclude(e.currentTarget.value); invalidate(); }} />
        <Textarea label="Exclude addresses or ranges" value={exclude} autosize minRows={2} maxRows={6} ff="monospace"
          description="Excluded addresses are removed from these discovery search ranges only. Inventory authorization is unchanged."
          onChange={(e) => { setExclude(e.currentTarget.value); invalidate(); }} />
        <Select label="Scanner vantage point" description="An authorized inventory scanner, or this service environment. In a container this is its network view, not the physical host."
          data={scannerChoices} value={scanner} allowDeselect={false} onChange={(value) => { setScanner(value ?? ''); invalidate(); }} />
        {targetsError && <Alert color="orange">Scanner inventory could not be refreshed: {targetsError}. Existing declarations are retained; the server rechecks scanner authorization on save.</Alert>}
        <Checkbox label="Allow public address space in this reviewed selection" checked={allowPublic} onChange={(e) => { setAllowPublic(e.currentTarget.checked); invalidate(); }} />
        {mixed && <Alert color="orange">
          <Text size="sm">The saved ranges use different public-address or scanner settings. This editor applies one policy to the resulting ranges. Cancel to preserve the existing policies, or explicitly choose their replacement.</Text>
          <Checkbox mt="xs" label="Replace the differing saved policies with the scanner/public settings shown above" checked={replacePolicies}
            onChange={(e) => { setReplacePolicies(e.currentTarget.checked); invalidate(); }} />
        </Alert>}
      </Stack>
    </fieldset>
    {inputProblem && <Alert color="orange">{inputProblem}</Alert>}
    <Button variant="light" disabled={!!inputProblem || changedElsewhere || previewing || saving} loading={previewing} onClick={() => void showPreview()}>Preview exact search ranges</Button>
    {preview && <ScopePreviewView preview={preview} />}
    {preview && <>
      {needsNormalizationAck && <>
        <Checkbox disabled={saving || previewing} label="I acknowledge the listed CIDR broadening for these exact inputs" checked={normalizationAccepted}
          onChange={(e) => { setNormalizationAccepted(e.currentTarget.checked); setConfirmed(false); }} />
        {normalizationAccepted !== previewAcknowledgement && <Text size="sm">Preview again with this acknowledgement before confirming the search ranges.</Text>}
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
      <Button variant="default" disabled={saving} onClick={() => { if (!saving) onClose(); }}>Cancel</Button>
      <Button disabled={!canSave || saving} loading={saving} onClick={() => void save()}>Confirm search ranges</Button>
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
