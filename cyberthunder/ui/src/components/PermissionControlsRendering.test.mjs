import assert from 'node:assert/strict';
import test from 'node:test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import * as Mantine from '@mantine/core';
import { evaluate, target } from '../lib/setupTestSupport.mjs';
import { proposal, helpers } from '../lib/rollbackTestSupport.mjs';

const h = React.createElement;
// Dialog layout is inlined for SSR; the tested buttons, switches, inputs and ARIA are real Mantine controls.
const dialog = ({ opened, title, children }) => opened ? h('section', { role: 'dialog' }, title, children) : null;
const core = { ...Mantine, Modal: dialog, Drawer: dialog };
const confirm = evaluate(new URL('./ConfirmReasonModal.tsx', import.meta.url), { '@mantine/core': core });
const gate = evaluate(new URL('./PermissionGate.tsx', import.meta.url), { '@mantine/core': core, './ConfirmReasonModal': confirm });
const provenance = evaluate(new URL('./IdentityProvenance.tsx', import.meta.url), { '@mantine/core': core });
const { PermissionProvider, PermissionButton, PermissionGate, PermissionConfirm, rolePermits } = gate;
const empty = () => null;
const common = {
  ErrorBox: ({ error }) => h('div', { role: 'alert' }, error), Loading: ({ what }) => h('p', {}, what),
  Mono: ({ children }) => h('code', {}, children), CodeBlock: empty, JsonView: empty,
  Collapsible: ({ title, children }) => h('div', {}, title, children),
  SeverityBadge: empty, StateBadge: empty, StatusBadge: empty, AssetIcon: empty, SimulatedBadge: empty,
  PageTitle: ({ title, subtitle, right }) => h('header', {}, h('h1', {}, title), h('p', {}, subtitle), right),
  AsyncView: ({ state, children }) => children(state.data), Empty: ({ title, action }) => h('div', {}, title, action),
};
const context = { actor: 'IT1 Reviewer', status: { kill: { engaged: false } }, statusError: null, refresh: async () => {} };
const appState = { useAppState: () => context, useAuditListener() {} };
const format = { fmtAgo: () => 'earlier', fmtTime: (v) => v, fmtZonedTime: (v) => v, label: (v) => v, severityRank: () => 1, ageSeconds: () => 1 };
const assurance = evaluate(new URL('../lib/findingAssurance.ts', import.meta.url));
const notice = { notifications: { show() {} } };
const source = (name, imports = {}) => evaluate(new URL(name, import.meta.url), {
  '@mantine/core': core, '@mantine/notifications': notice,
  '../api/client': { api: {}, errorText: (e) => e.message }, '../lib/format': format,
  '../state/AppState': appState, './PermissionGate': gate, '../components/PermissionGate': gate,
  './IdentityProvenance': provenance,
  './common': common, '../components/common': common, ...imports,
});
const asyncState = (data) => ({ data, loading: false, error: null, setData() {}, reload: async () => {} });
const hooksFor = (...responses) => {
  let i = 0;
  return { useAsync: () => asyncState(responses[i++]), useInterval() {}, useLocalPref: (_key, value) => React.useState(value) };
};
const cards = source('./ProposalCard.tsx', {
  './ApprovalProgress': source('./ApprovalProgress.tsx'),
  '../lib/proposalHistory': helpers, '../lib/findingAssurance': assurance,
  './ApplyTimeline': { ApplyTimeline: empty }, './CitationChips': { CitationChips: empty },
  './ProposalDiff': { DiffButton: () => h(Mantine.Button, {}, 'Diff') },
  './ProposalPlan': { PreviewButton: () => h(Mantine.Button, {}, 'Preview change') }, './FixPanel': { RiskTagsForFix: empty },
});
const actions = { approve() {}, deny() {}, apply() {}, rollback() {}, verify() {}, impact() {}, openFinding() {} };
const render = (component, props, permissions = [], withProvider = true) => {
  const content = h(component, props);
  return renderToStaticMarkup(h(Mantine.MantineProvider, {}, withProvider
    ? h(PermissionProvider, { can: typeof permissions === 'function' ? permissions : (action) => rolePermits(permissions, action) }, content) : content));
};
const button = (html, label) => {
  const match = [...html.matchAll(/<button\b[^>]*>[\s\S]*?<\/button>/g)].map((m) => m[0]).find((tag) => tag.includes(`>${label}<`));
  assert.ok(match, `Missing rendered button: ${label}`);
  return match;
};
const disabled = /\sdisabled(?:=|\s|>)/;
const denied = (html, label, action) => {
  const control = button(html, label);
  assert.match(control, disabled);
  const ids = /aria-describedby="([^"]+)"/.exec(control)?.[1].split(' ');
  assert.ok(ids?.length, `${label}: missing accessible explanation`);
  assert.ok(ids.some((id) => html.includes(`id="${id}"`)), `${label}: broken ARIA reference`);
  assert.ok(html.includes(`${action} permission required`), `${label}: missing action-specific reason`);
  assert.match(html, /role="group" tabindex="0" aria-disabled="true"/);
};

test('permission controls deny missing, malformed and throwing permission sources; no wildcard or admin inference', () => {
  assert.equal(rolePermits(['admin'], 'apply'), false);
  assert.equal(rolePermits(['*'], 'apply'), false);
  assert.equal(rolePermits(null, 'apply'), false);
  assert.equal(rolePermits('apply', 'apply'), false);
  for (const can of [() => false, () => 'true', () => { throw new Error('Unavailable'); }]) {
    denied(render(PermissionButton, { action: 'apply', children: 'Apply' }, can), 'Apply', 'apply');
  }
  const missing = render(PermissionButton, { action: 'apply', children: 'Apply' }, [], false);
  assert.match(button(missing, 'Apply'), disabled);
  assert.match(missing, /Account permissions are unavailable/);
});

test('explicit allow does not override busy or existing disabled state; permission reasons are escaped', () => {
  assert.doesNotMatch(button(render(PermissionButton, { action: 'apply', children: 'Apply' }, ['apply']), 'Apply'), disabled);
  assert.match(button(render(PermissionButton, { action: 'apply', children: 'Apply', disabled: true }, ['apply']), 'Apply'), disabled);
  const html = render(PermissionGate, { allowed: false, reason: 'No <script>access</script>',
    children: h(Mantine.Button, { 'aria-describedby': 'existing-note' }, 'Save') });
  assert.match(button(html, 'Save'), /aria-describedby="existing-note /);
  assert.match(html, /No &lt;script&gt;access&lt;\/script&gt;/);
  assert.doesNotMatch(html, /<script>/);
});

test('proposal controls independently honor approve, deny, plan, apply, rollback and verify permissions', () => {
  let html = render(cards.ProposalCard, { p: proposal('proposed', 'change'), actions }, ['plan']);
  denied(html, 'Approve', 'approve'); denied(html, 'Deny', 'deny');
  assert.doesNotMatch(button(html, 'Assess impact'), disabled);
  assert.doesNotMatch(button(html, 'Finding detail'), disabled);
  html = render(cards.ProposalCard, { p: proposal('proposed', 'change'), actions }, ['approve', 'plan']);
  assert.doesNotMatch(button(html, 'Approve'), disabled); denied(html, 'Deny', 'deny');
  html = render(cards.ProposalCard, { p: proposal('approved', 'change'), actions }, ['admin']);
  denied(html, 'Apply', 'apply'); denied(html, 'Preview change', 'plan');
  html = render(cards.ProposalCard, { p: { ...proposal('applied', 'change'), fix: { kind: 'runbook' } }, actions }, ['rollback']);
  assert.doesNotMatch(button(html, 'Rollback'), disabled); denied(html, 'Verify', 'verify');
  html = render(cards.ProposalCard, { p: proposal('verified', 'change'), actions, actionsDisabled: true }, []);
  assert.doesNotMatch(button(html, 'View impact receipt'), disabled);
});

test('Decisions disables role actions while search, filters, selection and refresh remain usable', () => {
  const { default: Decisions } = source('../pages/Decisions.tsx', {
    '../lib/hooks': hooksFor([proposal('proposed', 'pending'), proposal('approved', 'approved')]),
    '../lib/proposalHistory': helpers, '../lib/findingAssurance': assurance,
    '../api/types': { ASSET_TYPES: ['linux'] }, '@mantine/hooks': { useHotkeys() {} },
    'react-router-dom': { useNavigate: () => () => {}, useSearchParams: () => [new URLSearchParams(), () => {}] },
    '../components/ActorChip': { actorProblem: () => null }, '../components/ProposalCard': cards,
    '../components/FindingDrawer': { FindingDrawer: empty }, '../components/ImpactReview': { ImpactReview: empty },
    '../components/RollbackConfirmation': { RollbackConfirmation: empty },
  });
  const html = render(Decisions, {}, ['read']);
  denied(html, 'Approve', 'approve'); denied(html, 'Apply', 'apply'); denied(html, 'Deny selected', 'deny');
  assert.doesNotMatch(button(html, 'Clear filters'), disabled);
  assert.doesNotMatch(button(html, 'Refresh'), disabled);
  for (const input of html.matchAll(/<input\b[^>]*>/g)) assert.doesNotMatch(input[0], disabled, 'A readable filter or selection was disabled');
});

test('engage and release kill controls are independent, and lost permissions disable an open confirmation', () => {
  const { KillSwitch } = source('./KillSwitch.tsx');
  context.status.kill.engaged = false;
  assert.doesNotMatch(button(render(KillSwitch, {}, ['kill.engage']), 'KILL SWITCH'), disabled);
  denied(render(KillSwitch, {}, ['read']), 'KILL SWITCH', 'kill.engage');
  context.status.kill.engaged = true;
  denied(render(KillSwitch, {}, ['kill.engage']), 'Release', 'kill.release');
  assert.doesNotMatch(button(render(KillSwitch, {}, ['kill.release']), 'Release'), disabled);
  context.status.kill.engaged = false;
  const html = render(PermissionConfirm, { action: 'kill.release', opened: true, title: 'Release?', confirmLabel: 'Release', onClose() {}, onConfirm() {} }, ['kill.engage']);
  denied(html, 'Release', 'kill.release'); assert.doesNotMatch(button(html, 'Cancel'), disabled);
});

test('policy editing requires policy permission while read-only saved-policy evaluation stays enabled', () => {
  const { PolicyEditor } = source('./PolicyEditor.tsx', { '../lib/hooks': hooksFor({ enabled: false, version: 1, rules: [] }) });
  const html = render(PolicyEditor, {}, ['read']);
  denied(html, 'Add rule', 'policy'); denied(html, 'Save rules', 'policy');
  assert.doesNotMatch(button(html, 'Evaluate against current queue'), disabled);
  assert.match(html, /<fieldset disabled/);
  assert.match(html, /<input[^>]*disabled=""[^>]*type="checkbox"/);
});

test('FindingDrawer keeps evidence and review history readable while explain, propose and review are denied', () => {
  const finding = { id: 'finding', title: 'Recorded finding', host: 'fixture', rule_id: 'rule', status: 'open', severity: 'medium',
    source: 'fixture', references: [], evidence: 'Recorded evidence', fix: { title: 'Vetted fix', fix_ref: 'fix' },
    review: { disposition: 'unreviewed', history_count: 0 } };
  const readAccess = source('./FindingActions.tsx', {
    '../lib/hooks': hooksFor(undefined), '../lib/findingAssurance': assurance,
    './FindingReviewPanel': { FindingReviewPanel: () => h('form', {}, h(Mantine.Button, {}, 'Save review')) },
    './FindingAssurance': { ReviewBadge: empty },
  });
  const drawer = source('./FindingDrawer.tsx', { '../lib/hooks': hooksFor(finding, []),
    '../lib/findingAssurance': assurance, '../lib/findingRow': { findingResultLabel: () => 'Failed' },
    './CitationChips': { CitationChips: empty }, './FixPanel': { RiskTagsForFix: empty },
    './ProposalDiff': { DiffButton: empty }, './FindingAssurance': { ConfidenceBadge: empty }, './FindingActions': readAccess,
  });
  const html = render(drawer.FindingDrawer, { findingId: 'finding', onClose() {} }, ['read']);
  denied(html, 'Generate', 'explain'); denied(html, 'Propose fix', 'propose'); denied(html, 'Record review', 'review');
  assert.doesNotMatch(button(html, 'Show review history'), disabled);
  assert.doesNotMatch(html, /Save review/);
  assert.match(html, /Recorded finding/);
});

test('asset management and collection are distinct permissions; inventory refresh remains enabled', () => {
  const { default: Assets } = source('../pages/Assets.tsx', {
    '../lib/hooks': hooksFor([target({ in_scope: true })], { findings: [] }.findings),
    '../components/setupAccess': { useSetupAccess: () => null }, '../components/DiscoveryPanel': { DiscoveryPanel: empty },
    '../components/TargetForm': { TargetForm: empty }, '../components/HostSetup': { HostSetup: empty },
  });
  const html = render(Assets, {}, ['read', 'discover']);
  denied(html, 'Add asset', 'admin'); denied(html, 'Set up deployment host', 'admin');
  assert.doesNotMatch(button(html, 'Read asset facts'), disabled);
  assert.doesNotMatch(button(html, 'Refresh'), disabled);
  assert.match(html, /<input[^>]*disabled=""[^>]*type="checkbox"/);
});

test('direct TargetForm entry cannot expose an enabled save to a caller lacking admin', () => {
  const { TargetForm } = source('./TargetForm.tsx', { './setupAccess': { useSetupAccess: () => null },
    '../api/types': { ASSET_TYPES: ['linux'], TRANSPORTS: ['ssh'] } });
  const html = render(TargetForm, { opened: true, initial: target(), onSaved() {}, onClose() {} }, ['read']);
  denied(html, 'Save', 'admin'); assert.doesNotMatch(button(html, 'Cancel'), disabled);
});
