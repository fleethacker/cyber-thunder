import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import test, { after, mock } from 'node:test';
import { createElement as h } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createModuleLoader } from '../lib/moduleTestSupport.mjs';

const require = createRequire(import.meta.url);
const core = require('@mantine/core');
const load = createModuleLoader();
const { FindingCatalogReference } = load(new URL('./FindingCatalogReference.tsx', import.meta.url));
const network = mock.method(globalThis, 'fetch', () => { throw new Error('Unexpected network access'); });
after(() => assert.equal(network.mock.callCount(), 0));
const render = (component, props) => renderToStaticMarkup(h(core.MantineProvider, {}, h(component, props)));
const visible = (html) => html.replace(/<style\b[^>]*>[\s\S]*?<\/style>/g, '').replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
const panel = (metadata = annotation(), changes = {}) => render(FindingCatalogReference, { finding: { ...finding(), ...changes, catalog_rule_metadata: metadata } });
const controls = (html) => [...html.matchAll(/<button\b[^>]*>[\s\S]*?<\/button>/g)].map(([button]) => visible(button));

function finding() {
  return { id: 'native-finding', host: 'fixture-host', source: 'windows-stig', rule_id: 'SV-100001r1_rule',
    rule_version: 'WN11-00-000001', group_id: 'V-100001', title: 'Native checked title', severity: 'low', status: 'not_a_finding',
    benchmark: 'Bundled benchmark', benchmark_release: 'Bundled release V1R1', references: [], evidence: 'Original scanner evidence',
    description: 'Native description', check_text: 'Native check instructions', fix_text: 'Native fix instructions',
    collected_at: '2026-11-05T12:00:00Z', asset_type: 'windows', explanation: null,
    confidence: { grade: 'low', reason: 'Original confidence reason', reasons: [] },
    review: { active: true, suppressed: true, disposition: 'false_positive', current: { reason: 'Original human decision', reviewed_by: 'Fixture operator' } },
    fix: { title: 'Vetted original fix', fix_ref: 'fixture:original', disruption: 'low', reboot: false, restarts_services: [], reversible: true, rollback_plan: 'Original rollback' } };
}

// Mirrors the v1 annotation constructed by catalog_rule_metadata.py and its isolated fixture tests.
// coverage_added belongs to the collection summary, not this finding field.
function annotation(mapping = 'matched') {
  const f = finding();
  const active = ['matched', 'withdrawn', 'missing', 'ambiguous'].includes(mapping);
  const hasRule = ['matched', 'withdrawn'].includes(mapping);
  const catalog = { status: active ? 'active_catalog' : mapping };
  if (mapping !== 'not_configured') catalog.binding = { product_key: 'MS_Windows_11', benchmark_id: 'Fixture_Benchmark' };
  if (active || mapping === 'untrusted_active_catalog') Object.assign(catalog, {
    benchmark_id: 'Fixture_Benchmark', release_scheme: 'disa', release: [2, 10],
    publication_generation: 'publication-generation-4', source_sha256: 'a'.repeat(64), source_bytes: 1234,
    source: 'imported', filename: 'fixture-10.xml', commit_status: 'committed_with_bookkeeping_pending',
    authenticity: { status: 'operator_attested', operator_attested: true, disa_signature: false,
      document_sha256: 'e'.repeat(64), key_sha256: 'b'.repeat(64) },
  });
  if (active) Object.assign(catalog, { benchmark_title: 'Reference benchmark title', benchmark_version: '2',
    benchmark_release: 'Release: 10 Benchmark Date: 01 Jan 2025', catalog_sha256: 'c'.repeat(64), catalog_bytes: 1100, catalog_rule_count: 200 });
  if (mapping === 'untrusted_active_catalog') catalog.authenticity = { status: 'unsigned_dev', operator_attested: false, disa_signature: false };
  return { version: 1, family: 'windows11', assessment: 'not_assessed',
    snapshot_generation: mapping === 'not_configured' ? null : 'snapshot-generation-7', catalog,
    native: { finding_id: f.id, source: f.source, rule_id: f.rule_id, stig_id: f.rule_version,
      benchmark: f.benchmark, benchmark_release: f.benchmark_release, status: f.status },
    bundled: { source: 'bundled_extract', path: 'adapters/windows/w11_catalog.json', sha256: 'd'.repeat(64) },
    mapping_status: mapping, metadata_source: hasRule ? 'active_catalog' : 'bundled_extract',
    ...(hasRule ? { rule: { rule_id: 'SV-100001r10_rule', stig_id: f.rule_version, group_id: 'V-100001',
      title: 'Reference title for release 10', severity: 'high', cci: ['CCI-000366'] } } : {}),
  };
}

test('matched reference keeps the checked release separate and labels zero added coverage and no assessment', () => {
  const html = panel(), text = visible(html);
  for (const phrase of ['Checked native release Native benchmark: Bundled benchmark Native release: Bundled release V1R1',
    'Reference match found', 'Not assessed', 'adds 0 checks of coverage', 'does not establish that the native checker assesses the catalog release',
    'does not change evidence confidence or approvals', 'Active catalog at collection', 'Product: MS_Windows_11',
    'Catalog benchmark ID: Fixture_Benchmark', 'Catalog title: Reference benchmark title', 'Catalog version: 2',
    'Catalog release text: Release: 10 Benchmark Date: 01 Jan 2025', 'Release scheme: disa', 'Release values: 2 / 10',
    'Catalog state (recorded): active_catalog', 'Reference title: Reference title for release 10', 'Reference severity: high',
    'Reference rule ID: SV-100001r10_rule', 'Stable STIG ID: WN11-00-000001', 'Reference group ID: V-100001', 'CCI-000366',
    'platform applicability is not established', 'does not establish present activation or the newest available release']) assert.ok(text.includes(phrase), phrase);
  assert.doesNotMatch(html, /<a\b|<button\b|<input\b|<form\b|<iframe\b/);
});

test('recorded provenance distinguishes operator attestation from publisher signing and collapses technical receipts', () => {
  const html = panel(), text = visible(html);
  for (const phrase of ['Operator attestation recorded as verified at import; no publisher signature.', 'Evidence status: operator_attested',
    'Publication status: committed_with_bookkeeping_pending', 'Source type: imported', 'Source filename: fixture-10.xml']) assert.ok(text.includes(phrase), phrase);
  assert.doesNotMatch(text, /Operator signer|Attestation scope/);
  const details = /<details>([\s\S]*?)<\/details>/.exec(html)?.[1];
  assert.ok(details, 'Provenance details start collapsed');
  assert.doesNotMatch(html, /<details[^>]*\bopen/);
  for (const receipt of ['snapshot-generation-7', 'publication-generation-4', 'adapters/windows/w11_catalog.json',
    'a'.repeat(64), 'b'.repeat(64), 'c'.repeat(64), 'd'.repeat(64), 'e'.repeat(64), '1234', '1100', '200']) assert.ok(details.includes(receipt), receipt);
  assert.match(visible(details), /Catalog rule count \(not coverage\): 200/);
});

for (const [status, label, explanation] of [
  ['missing', 'Rule missing', 'Absence alone does not establish withdrawal'],
  ['withdrawn', 'Rule marked withdrawn', 'withdrawn, deprecated or obsolete'],
  ['ambiguous', 'Ambiguous reference', 'No reference rule is selected'],
  ['no_active_catalog', 'No active catalog', 'no active manual catalog in the recorded snapshot'],
  ['untrusted_active_catalog', 'Untrusted active catalog', 'Its rule metadata was not used'],
  ['not_configured', 'Not configured', 'No local catalog was requested or read'],
]) test(`${status} is explicit and never substituted with a catalog pass`, () => {
  const value = annotation(status);
  if (status !== 'withdrawn') value.rule = { title: 'Unexpected rule must not appear', rule_id: 'unrelated-id' };
  const text = visible(panel(value));
  assert.ok(text.includes(label)); assert.ok(text.includes(explanation));
  assert.match(text, /Not assessed/); assert.match(text, /adds 0 checks of coverage/);
  assert.doesNotMatch(text, /Reference unavailable|Unexpected rule|unrelated-id|Reference match found|catalog pass/i);
  if (['no_active_catalog', 'not_configured'].includes(status)) assert.doesNotMatch(text, /Active catalog at collection|Publication evidence/);
  if (status === 'untrusted_active_catalog') assert.match(text, /Unsigned development content; authenticity not established/);
});

test('old findings without an annotation leave the drawer unchanged', () => {
  assert.equal(visible(render(FindingCatalogReference, { finding: finding() })), '');
  assert.equal(visible(panel(null)), '');
});

test('not-configured annotations cannot display stray catalog identities as a selected reference', () => {
  const value = annotation('not_configured');
  value.catalog.binding = { product_key: 'Unexpected product', benchmark_id: 'Unexpected benchmark' };
  value.catalog.benchmark_title = 'Unexpected catalog';
  const html = panel(value);
  assert.match(html, /No local catalog was requested or read/);
  assert.doesNotMatch(html, /Selected catalog|Unexpected product|Unexpected benchmark|Unexpected catalog/);
});

for (const [label, change] of [
  ['unsupported version', (m) => { m.version = 2; }],
  ['missing assessment', (m) => { delete m.assessment; }],
  ['claimed catalog pass', (m) => { m.assessment = 'pass'; }],
  ['unknown mapping', (m) => { m.mapping_status = 'constructor'; }],
  ['wrong catalog state', (m) => { m.catalog.status = 'untrusted_active_catalog'; }],
  ['wrong metadata source', (m) => { m.metadata_source = 'bundled_extract'; }],
  ['other finding', (m) => { m.native.finding_id = 'other-finding'; }],
  ['other native rule', (m) => { m.native.rule_id = 'other-rule'; }],
  ['other native release', (m) => { m.native.benchmark_release = 'Other release'; }],
  ['other scanner result', (m) => { m.native.status = 'open'; }],
  ['wrong reference STIG ID', (m) => { m.rule.stig_id = 'OTHER-000001'; }],
  ['wrong benchmark identity', (m) => { m.catalog.benchmark_id = 'Other benchmark'; }],
  ['missing product', (m) => { m.catalog.binding.product_key = null; }],
  ['missing rule', (m) => { m.rule = null; }],
]) test(`${label} degrades to an unavailable reference without replacing native release evidence`, () => {
  const value = annotation(); change(value);
  const text = visible(panel(value));
  assert.match(text, /Reference unavailable/); assert.match(text, /Finding release: Bundled release V1R1/);
  assert.doesNotMatch(text, /Reference match found|Reference title for release 10|Active catalog at collection/);
});

test('malformed envelope and nested values never throw or stringify objects', () => {
  for (const value of [false, 1, 'metadata', [], {}, { catalog: [] }, { ...annotation(), native: [] }]) {
    const html = panel(value);
    assert.match(html, /Reference unavailable/); assert.doesNotMatch(html, /\[object Object\]/);
  }
  const value = annotation();
  Object.assign(value.catalog, { benchmark_title: {}, benchmark_version: 2, benchmark_release: [], release: [2, '10'],
    authenticity: [], source_bytes: -1, catalog_rule_count: NaN, catalog_sha256: 'invalid', publication_generation: {} });
  Object.assign(value.rule, { title: {}, severity: [], rule_id: null, cci: ['CCI-000366', {}] });
  const text = visible(panel(value));
  for (const label of ['Catalog title', 'Catalog version', 'Catalog release text', 'Release values', 'Reference title',
    'Reference severity', 'Reference rule ID', 'Reference CCIs', 'Source package bytes', 'Catalog rule count (not coverage)',
    'Catalog SHA-256', 'Publication generation']) assert.ok(text.includes(`${label}: Not recorded or unsupported`), label);
  assert.match(text, /Publication evidence is incomplete or unsupported/);
  assert.doesNotMatch(text, /\[object Object\]|verified at import|Reference severity: low/);
});

test('oversized strings and lists have explicit placeholders rather than partial identities or unbounded output', () => {
  const value = annotation(), large = 'OVERSIZE'.repeat(1000);
  value.catalog.benchmark_title = large; value.catalog.release = Array(1000).fill(1);
  value.rule.title = large; value.rule.cci = Array(1000).fill('CCI-000366');
  const html = panel(value), text = visible(html);
  assert.doesNotMatch(html, /OVERSIZE|CCI-000366/);
  for (const label of ['Catalog title', 'Reference title', 'Release values', 'Reference CCIs']) assert.ok(text.includes(`${label}: Not recorded or unsupported`));
  const supported = annotation(); supported.rule.title = 't'.repeat(4096);
  assert.ok(panel(supported).includes(supported.rule.title), 'The public contract permits bounded text through 4096 characters');
  value.catalog.binding.benchmark_id = large;
  assert.match(panel(value), /Reference unavailable/);
});

test('untrusted metadata renders only escaped text, with no metadata links, HTML, scripts or executable fields', () => {
  const value = annotation(), hostile = '<img src=x onerror=alert(1)> & <script>alert("x")</script> https://example.invalid/x';
  for (const name of ['benchmark_title', 'benchmark_release', 'source', 'filename']) value.catalog[name] = hostile;
  value.rule.title = hostile; value.rule.rule_id = 'javascript:alert(1)';
  Object.assign(value.catalog.authenticity, { signer: 'PRIVATE_SIGNER', scope: 'PRIVATE_SCOPE',
    override_by: 'PRIVATE_ACTOR', override_reason: 'PRIVATE_REASON', url: 'PRIVATE_URL', key_path: 'PRIVATE_PATH' });
  value.catalog.url = 'https://example.invalid/metadata-url';
  value.rule.check_text = value.rule.fix_text = value.rule.script = 'NEVER DISPLAY IMPORTED EXECUTION TEXT';
  const html = panel(value);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt; &amp; &lt;script&gt;alert\(&quot;x&quot;\)&lt;\/script&gt;/);
  assert.match(html, /javascript:alert\(1\)/);
  assert.doesNotMatch(html, /<img\b|<script\b|<a\b|<iframe\b|metadata-url|NEVER DISPLAY|PRIVATE_/);
});

for (const [label, evidence, expected] of [
  ['human exception', { status: 'human_override', operator_attested: false, disa_signature: false, unverified_status: 'unknown_signer' }, 'Authorized human exception recorded; authenticity not established'],
  ['HTTPS receipt', { status: 'trusted_https_source', operator_attested: false, disa_signature: false }, 'Verified HTTPS source recorded at import; no publisher signature'],
  ['missing evidence', null, 'Publication evidence is incomplete or unsupported'],
  ['legacy evidence', { status: 'legacy_unverified', disa_signature: false }, 'Publication evidence is incomplete or unsupported'],
  ['string boolean', { status: 'operator_attested', operator_attested: 'true', disa_signature: false }, 'Publication evidence is incomplete or unsupported'],
  ['publisher signature claim', { status: 'operator_attested', operator_attested: true, disa_signature: true }, 'publisher signing is not established'],
  ['inconsistent exception', { status: 'human_override', operator_attested: true, disa_signature: false }, 'Publication evidence is incomplete or unsupported'],
]) test(`${label} does not upgrade a receipt into publisher trust`, () => {
  const value = annotation(); value.catalog.authenticity = evidence;
  const text = visible(panel(value));
  assert.ok(text.includes(expected)); assert.doesNotMatch(text, /Operator attestation recorded as verified/);
  if (label === 'human exception') {
    assert.match(text, /Original evidence status: unknown_signer/);
    evidence.override_by = 'PRIVATE_ACTOR'; evidence.override_reason = 'PRIVATE_REASON';
    assert.doesNotMatch(panel(value), /PRIVATE_|Exception recorded by|Exception reason/);
    evidence.unverified_status = { toString: null };
    assert.match(visible(panel(value)), /Original evidence status: Not recorded or unsupported/);
  }
});

function drawer(f) {
  const load = createModuleLoader();
  load(new URL('../lib/format.ts', import.meta.url), {
    dayjs: { default: require('dayjs') }, 'dayjs/plugin/relativeTime': { default: require('dayjs/plugin/relativeTime') },
  });
  let read = 0;
  // Inline the portal only; real drawer content, React state, Mantine widgets and child components render.
  const { FindingDrawer } = load(new URL('./FindingDrawer.tsx', import.meta.url), {
    '@mantine/core': { ...core, Drawer: ({ opened, title, children }) => opened ? h('section', { role: 'dialog' }, title, children) : null },
    '../lib/hooks': { useAsync: () => ({ data: read++ === 0 ? f : [], loading: false, error: null, setData() {}, reload: async () => {} }) },
  });
  const { PermissionProvider } = load(new URL('./PermissionGate.tsx', import.meta.url));
  return renderToStaticMarkup(h(core.MantineProvider, {}, h(PermissionProvider, { can: (action) => ['explain', 'propose'].includes(action) },
    h(FindingDrawer, { findingId: f.id, onClose() {} }))));
}

test('drawer integration preserves native evidence, result, confidence, human review and existing action states for every mapping', () => {
  const baseline = drawer(finding());
  const baselineControls = [...baseline.matchAll(/<button\b[^>]*>[\s\S]*?<\/button>/g)].map(([button]) => [visible(button), /\sdisabled(?:=|\s|>)/.test(button)]);
  for (const mapping of ['matched', 'withdrawn', 'missing', 'ambiguous', 'not_configured', 'no_active_catalog', 'untrusted_active_catalog']) {
    const f = { ...finding(), catalog_rule_metadata: annotation(mapping) }, before = structuredClone(f);
    const html = drawer(f), text = visible(html);
    assert.deepEqual(f, before, 'Rendering cannot mutate the finding');
    for (const phrase of ['Native checked title', 'Original scanner evidence', 'Original confidence reason', 'Original human decision',
      'SV-100001r1_rule', 'Bundled release V1R1', 'Scanner observation', 'not_a_finding', 'Vetted original fix', 'Original rollback']) assert.ok(text.includes(phrase), phrase);
    assert.match(html, /aria-label="Low confidence: show reasons"/);
    assert.match(text, /CAT III/);
    assert.deepEqual([...html.matchAll(/<button\b[^>]*>[\s\S]*?<\/button>/g)].map(([button]) => [visible(button), /\sdisabled(?:=|\s|>)/.test(button)]), baselineControls);
    assert.deepEqual(controls(html), controls(baseline));
    assert.ok(text.indexOf('Original scanner evidence') < text.indexOf('Catalog reference'));
    assert.ok(text.indexOf('Original human decision') < text.indexOf('Catalog reference'));
  }
});

test('drawer integration tolerates malformed annotation and preserves legacy content with no panel', () => {
  const html = drawer({ ...finding(), catalog_rule_metadata: { ...annotation(), catalog: [] } });
  assert.match(html, /Reference unavailable/); assert.match(html, /Original scanner evidence/);
  assert.match(html, /Original human decision/); assert.match(html, /Native checked title/);
  assert.doesNotMatch(drawer(finding()), /Catalog reference|Reference unavailable/);
});

test('a remediated finding uses its original scanner status for annotation identity without changing either result', () => {
  const f = { ...finding(), status: 'not_a_finding', scanner_status: 'open', review: null, catalog_rule_metadata: annotation() };
  f.catalog_rule_metadata.native.status = 'open';
  const html = drawer(f);
  assert.match(html, /Reference match found/); assert.doesNotMatch(html, /Reference unavailable/);
  assert.match(visible(html), /Original result: open open/);
  assert.equal(f.status, 'not_a_finding'); assert.equal(f.scanner_status, 'open');
});

test('malformed annotations on external scanner findings do not relabel their release as native', () => {
  const html = panel(annotation(), { source: 'openscap', benchmark: 'External scanner benchmark', benchmark_release: 'External release' });
  assert.match(visible(html), /Finding benchmark: External scanner benchmark Finding release: External release/);
  assert.match(html, /Reference unavailable/); assert.doesNotMatch(html, /Checked native release|Native benchmark|Native release/);
});

test('catalog metadata cannot enable or disable an otherwise available proposal action', () => {
  const f = { ...finding(), status: 'open', review: null };
  const value = annotation(); value.native.status = 'open';
  const before = drawer(f), after = drawer({ ...f, catalog_rule_metadata: value });
  const propose = (html) => [...html.matchAll(/<button\b[^>]*>[\s\S]*?<\/button>/g)].map(([button]) => button).find((button) => visible(button) === 'Propose fix');
  assert.ok(propose(before)); assert.ok(propose(after));
  assert.doesNotMatch(propose(before), /\sdisabled(?:=|\s|>)/);
  assert.doesNotMatch(propose(after), /\sdisabled(?:=|\s|>)/);
});
