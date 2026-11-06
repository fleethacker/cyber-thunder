import { Alert, Badge, Group, Paper, Stack, Text } from '@mantine/core';
import type { FindingPlus } from '../api/types';

type Fields = Record<string, unknown>;
const unavailable = 'Not recorded or unsupported';
const record = (value: unknown): Fields | null =>
  value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Fields : null;
// Do not stringify arbitrary objects or silently shorten identities and release values.
const text = (value: unknown): string | null =>
  typeof value === 'string' && value.length <= 4096 && value.trim() ? value : null;
const count = (value: unknown): string =>
  typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? String(value) : unavailable;
const hash = (value: unknown): string =>
  typeof value === 'string' && /^[a-fA-F0-9]{64}$/.test(value) ? value : unavailable;

const outcomes = {
  matched: ['Reference match found', 'One catalog rule matches the stable STIG ID. This does not establish that the native checker assesses this release.'],
  missing: ['Rule missing', 'The exact stable STIG ID is absent from this catalog. Absence alone does not establish withdrawal.'],
  withdrawn: ['Rule marked withdrawn', 'The rule or benchmark is marked withdrawn, deprecated or obsolete. The recorded native observation remains unchanged.'],
  ambiguous: ['Ambiguous reference', 'The catalog does not provide a unique rule mapping. No reference rule is selected.'],
  no_active_catalog: ['No active catalog', 'The selected lineage had no active manual catalog in the recorded snapshot.'],
  untrusted_active_catalog: ['Untrusted active catalog', 'The active publication was untrusted for this reference. Its rule metadata was not used.'],
  not_configured: ['Not configured', 'No local catalog was requested or read for this native check.'],
} as const;
type Mapping = keyof typeof outcomes;

function referenceFor(finding: FindingPlus) {
  const metadata = record(finding.catalog_rule_metadata);
  const catalog = record(metadata?.catalog);
  const native = record(metadata?.native);
  const status = text(metadata?.mapping_status);
  if (!metadata || !catalog || !native || metadata.version !== 1 || metadata.assessment !== 'not_assessed'
    || !status || !Object.prototype.hasOwnProperty.call(outcomes, status)) return null;
  // Bind the annotation to the observed finding, including its original scanner result.
  if (native.finding_id !== finding.id || native.source !== finding.source || native.rule_id !== finding.rule_id
    || !text(native.stig_id) || native.stig_id !== finding.rule_version
    || native.benchmark !== finding.benchmark || native.benchmark_release !== finding.benchmark_release
    || native.status !== (finding.scanner_status ?? finding.remediated?.scan_status ?? finding.status)) return null;
  const mapping = status as Mapping;
  const active = ['matched', 'missing', 'withdrawn', 'ambiguous'].includes(mapping);
  const hasRule = mapping === 'matched' || mapping === 'withdrawn';
  if (catalog.status !== (active ? 'active_catalog' : mapping)
    || metadata.metadata_source !== (hasRule ? 'active_catalog' : 'bundled_extract')) return null;
  const binding = mapping === 'not_configured' ? null : record(catalog.binding);
  if (mapping !== 'not_configured' && (!text(binding?.product_key) || !text(binding?.benchmark_id))) return null;
  if ((active || mapping === 'untrusted_active_catalog') && catalog.benchmark_id !== binding?.benchmark_id) return null;
  const rule = hasRule ? record(metadata.rule) : null;
  if (hasRule && (!rule || rule.stig_id !== native.stig_id)) return null;
  return { metadata, catalog, binding, rule, mapping, active };
}

function publicationEvidence(value: unknown): string {
  const evidence = record(value);
  // These are recorded receipts, not a new browser-side verification or trust decision.
  if (evidence?.disa_signature !== false) return 'Publication evidence is incomplete or unsupported; publisher signing is not established.';
  if (evidence.status === 'operator_attested' && evidence.operator_attested === true)
    return 'Operator attestation recorded as verified at import; no publisher signature.';
  if (evidence.status === 'trusted_https_source' && evidence.operator_attested === false)
    return 'Verified HTTPS source recorded at import; no publisher signature.';
  if (evidence.status === 'human_override' && evidence.operator_attested === false)
    return 'Authorized human exception recorded; authenticity not established. No publisher signature.';
  if (evidence.status === 'unsigned_dev' && evidence.operator_attested === false)
    return 'Unsigned development content; authenticity not established. No publisher signature.';
  return 'Publication evidence is incomplete or unsupported; authenticity and publisher signing are not established.';
}

function release(value: unknown): string {
  return Array.isArray(value) && value.length > 0 && value.length <= 4
    && value.every((part) => typeof part === 'number' && Number.isSafeInteger(part) && part >= 0)
    ? value.join(' / ') : unavailable;
}

function ccis(value: unknown): string {
  if (!Array.isArray(value) || value.length > 64 || !value.every((item) => typeof item === 'string' && /^CCI-\d{6}$/.test(item))) return unavailable;
  return value.length ? value.join(', ') : 'None recorded';
}

function Field({ label, value }: { label: string; value: unknown }) {
  return <Text size="sm" style={{ overflowWrap: 'anywhere', whiteSpace: 'pre-wrap' }}>
    <Text span fw={600}>{label}: </Text>{text(value) ?? unavailable}
  </Text>;
}

/** A saved reference only. Never feeds results, confidence, citations or action permissions. */
export function FindingCatalogReference({ finding }: { finding: FindingPlus }) {
  if (finding.catalog_rule_metadata == null) return null;
  const reference = referenceFor(finding);
  const catalog = reference?.catalog;
  const authenticity = record(catalog?.authenticity);
  const bundled = record(reference?.metadata.bundled);
  const publication = reference && (reference.active || reference.mapping === 'untrusted_active_catalog');
  return <Paper component="section" aria-label="Catalog reference" withBorder p="md" radius="md">
    <Stack gap="sm">
      <Group justify="space-between"><Text fw={700}>Catalog reference</Text><Badge color="orange" variant="light">Not assessed</Badge></Group>
      <Alert color="orange" title="Reference only — Not assessed">
        This reference adds 0 checks of coverage. A matching STIG ID does not establish that the native checker assesses the catalog release.
        {' '}It does not change evidence confidence or approvals.
      </Alert>
      <Stack gap={2}>
        <Text fw={600}>{reference ? 'Checked native release' : 'Recorded finding release'}</Text>
        <Field label={reference ? 'Native benchmark' : 'Finding benchmark'} value={finding.benchmark} />
        <Field label={reference ? 'Native release' : 'Finding release'} value={finding.benchmark_release} />
      </Stack>
      {!reference ? <Text size="sm" c="dimmed">Reference unavailable: the annotation is incomplete, inconsistent or unsupported. Use the original finding evidence above.</Text> : <>
        <Stack gap={2}>
          <Text fw={600}>{outcomes[reference.mapping][0]}</Text>
          <Text size="sm">{outcomes[reference.mapping][1]}</Text>
          <Field label="Mapping status" value={reference.mapping} />
        </Stack>
        {reference.binding && <Stack gap={2}>
          <Text fw={600}>{publication ? 'Active catalog at collection' : 'Selected catalog'}</Text>
          <Field label="Product" value={reference.binding.product_key} />
          <Field label="Selected benchmark ID" value={reference.binding.benchmark_id} />
          <Text size="xs" c="dimmed">The product and benchmark selection is an operator declaration; platform applicability is not established.</Text>
        </Stack>}
        {publication && <>
          <Stack gap={2}>
            <Field label="Catalog benchmark ID" value={catalog?.benchmark_id} />
            <Field label="Catalog title" value={catalog?.benchmark_title} />
            <Field label="Catalog version" value={catalog?.benchmark_version} />
            <Field label="Catalog release text" value={catalog?.benchmark_release} />
            <Field label="Release scheme" value={catalog?.release_scheme} />
            <Field label="Release values" value={release(catalog?.release)} />
            <Field label="Catalog state (recorded)" value={catalog?.status} />
          </Stack>
          {reference.rule && <Stack gap={2}>
            <Text fw={600}>Reference rule — Not assessed</Text>
            <Field label="Reference title" value={reference.rule.title} />
            <Field label="Reference severity" value={reference.rule.severity} />
            <Field label="Reference rule ID" value={reference.rule.rule_id} />
            <Field label="Stable STIG ID" value={reference.rule.stig_id} />
            <Field label="Reference group ID" value={reference.rule.group_id} />
            <Field label="Reference CCIs" value={ccis(reference.rule.cci)} />
          </Stack>}
          <Stack gap={2}>
            <Text fw={600}>Publication evidence (recorded)</Text>
            <Text size="sm">{publicationEvidence(authenticity)}</Text>
            <Field label="Evidence status" value={authenticity?.status} />
            <Field label="Publication status" value={catalog?.commit_status} />
            <Field label="Source type" value={catalog?.source} />
            <Field label="Source filename" value={catalog?.filename} />
            {authenticity?.status === 'human_override' && <Field label="Original evidence status"
              value={authenticity.unverified_status === 'unsigned' || authenticity.unverified_status === 'unknown_signer' ? authenticity.unverified_status : null} />}
          </Stack>
        </>}
        <Text size="xs" c="dimmed">This saved snapshot does not establish present activation or the newest available release.</Text>
        <details>
          <summary>Reference provenance details</summary>
          <Stack gap={2} mt="xs">
            <Field label="Native family" value={reference.metadata.family} />
            <Field label="Metadata source" value={reference.metadata.metadata_source} />
            <Field label="Snapshot generation" value={reference.metadata.snapshot_generation} />
            <Field label="Publication generation" value={catalog?.publication_generation} />
            <Field label="Bundled extract path" value={bundled?.path} />
            <Field label="Bundled extract SHA-256" value={hash(bundled?.sha256)} />
            {publication && <>
              <Field label="Source package SHA-256" value={hash(catalog?.source_sha256)} />
              <Field label="Source package bytes" value={count(catalog?.source_bytes)} />
              <Field label="Catalog SHA-256" value={hash(catalog?.catalog_sha256)} />
              <Field label="Catalog bytes" value={count(catalog?.catalog_bytes)} />
              <Field label="Catalog rule count (not coverage)" value={count(catalog?.catalog_rule_count)} />
              <Field label="Attestation key SHA-256" value={hash(authenticity?.key_sha256)} />
              <Field label="Attestation document SHA-256" value={hash(authenticity?.document_sha256)} />
            </>}
          </Stack>
        </details>
      </>}
    </Stack>
  </Paper>;
}
