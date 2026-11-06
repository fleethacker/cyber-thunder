import assert from 'node:assert/strict';
import test from 'node:test';
import { createRequire } from 'node:module';
import { createElement as h } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createModuleLoader } from '../lib/moduleTestSupport.mjs';
import { mount } from '../lib/setupTestSupport.mjs';
import { proposal } from '../lib/rollbackTestSupport.mjs';

// Use the same CommonJS Mantine instance as the in-memory TypeScript loader.
const require = createRequire(import.meta.url);
const Mantine = require('@mantine/core');
Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: { getItem: () => null } });

const dev = { mode: 'dev', authenticated: false, login_available: false, permissions: [] };
const evidence = (changes = {}) => ({ kind: 'human', iss: 'https://identity.example', sub: 'rivera-123',
  name: 'ITC Rivera', roles: ['approver'], via: 'oidc', verified: true, expires_at: 1, ...changes });
const secrets = { session_id: 'DO-NOT-RENDER-SESSION', access_token: 'DO-NOT-RENDER-ACCESS',
  id_token: 'DO-NOT-RENDER-ID', refresh_token: 'DO-NOT-RENDER-REFRESH', csrf_token: 'DO-NOT-RENDER-CSRF' };
const session = (changes = {}) => ({ mode: 'oidc', authenticated: true, login_available: true, permissions: ['review'],
  csrf_token: secrets.csrf_token, principal: { actor: 'human:current-user', name: 'Current Reviewer',
    issuer: 'https://current.example', subject: 'current-subject', source: 'oidc', roles: ['approver'], verified: true, ...secrets }, ...changes });
const event = (changes = {}) => ({ id: 'review', disposition: 'confirmed', reviewed_by: 'human:recorded-actor',
  reviewed_at: '2026-11-05T12:00:00Z', expires_at: '2026-11-05T13:00:00Z', reason: 'Checked the recorded evidence',
  supporting_evidence: '', identity_verified: true, reviewed_principal: evidence(), scope: {}, evidence_fingerprint: 'a'.repeat(64), ...changes });
const summary = (events) => ({ revision: events.length, disposition: 'confirmed', active: false, suppressed: false,
  evidence_fingerprint: 'a'.repeat(64), current: events.at(-1) ?? null, history: events, history_count: events.length,
  reopened_reason: 'Review expired', identity_verified: events.at(-1)?.identity_verified ?? false });
const plain = (html) => html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ');

function fixture() {
  const load = createModuleLoader();
  load(new URL('../lib/format.ts', import.meta.url), Object.fromEntries(
    ['dayjs', 'dayjs/plugin/relativeTime'].map((name) => [name, { default: require(name) }])));
  const components = load(new URL('./IdentityProvenance.tsx', import.meta.url));
  const { IdentityProvider } = load(new URL('../state/Identity.tsx', import.meta.url));
  const { AppStateProvider } = load(new URL('../state/AppState.tsx', import.meta.url));
  const { PermissionProvider } = load(new URL('./PermissionGate.tsx', import.meta.url));
  const renderNode = (node, identity = dev) => renderToStaticMarkup(h(Mantine.MantineProvider, {},
    h(IdentityProvider, { identity, logout: async () => {} }, h(AppStateProvider, {},
      h(PermissionProvider, { can: () => false }, node)))));
  return { ...components, load, renderNode, render: (component, props, identity) => renderNode(h(component, props), identity) };
}

test('saved review uses recorded human evidence, with source, issuer, subject, roles and audit actor', () => {
  const f = fixture();
  for (const via of ['oidc', 'mesh']) {
    const html = f.render(f.ReviewIdentity, { event: event({ reviewed_principal: evidence({ via, ...secrets }) }) }, session());
    for (const value of ['Reviewed by', 'ITC Rivera', `Verified at decision (${via === 'oidc' ? 'OIDC' : 'mesh'})`,
      'https://identity.example', 'rivera-123', 'approver', 'human:recorded-actor']) assert.ok(plain(html).includes(value), value);
    assert.doesNotMatch(html, /Current Reviewer|current-subject|Local \/ unverified/);
    for (const secret of Object.values(secrets)) assert.ok(!html.includes(secret));
  }
});

test('legacy and explicit local records stay unverified even when the current account is verified', () => {
  const f = fixture();
  for (const identity_verified of [false, undefined]) {
    const html = f.render(f.ReviewIdentity, { event: event({ reviewed_by: 'IT1 Local', identity_verified, reviewed_principal: undefined }) }, session());
    assert.match(plain(html), /Reviewed by IT1 Local/);
    assert.match(html, /Local \/ unverified identity/);
    assert.doesNotMatch(html, /Verified at decision|Current Reviewer/);
  }
});

test('a bare verified flag, inconsistent flag, workload, unknown source or incomplete evidence cannot claim a verified human decision', () => {
  const f = fixture();
  const cases = [
    { reviewed_principal: undefined }, { reviewed_principal: evidence({ verified: false }) },
    { identity_verified: false }, { identity_verified: 'true' },
    ...[{ kind: 'workload' }, { kind: 'dev', via: 'dev' }, { via: 'unknown' }, { verified: 'true' },
      { iss: '' }, { sub: null }, { name: '' }].map((bad) => ({ reviewed_principal: evidence(bad) })),
  ];
  for (const change of cases) {
    const html = f.render(f.ReviewIdentity, { event: event(change) });
    assert.doesNotMatch(html, /Verified at decision/);
    assert.match(html, /Identity verification unavailable|Local \/ unverified/);
  }
});

test('names and identifiers render as text, and unknown principal fields never enter the markup', () => {
  const f = fixture();
  const html = f.render(f.ReviewIdentity, { event: event({ reviewed_principal: evidence({
    name: 'Rivéra <img src=x onerror=alert(1)>', iss: 'https://issuer.example/<script>', sub: '<subject>&',
    roles: ['<approver>'], ...secrets, raw_claims: { confidential: 'DO-NOT-RENDER-CLAIMS' },
  }) }) });
  assert.match(html, /Rivéra &lt;img/); assert.match(html, /&lt;subject&gt;&amp;/);
  assert.doesNotMatch(html, /<img|<script|DO-NOT-RENDER|session_id|access_token|csrf_token|raw_claims/);
});

test('current reviewer uses the public session projection; dev and incomplete sessions are labeled honestly', () => {
  const f = fixture();
  const html = f.render(f.ReviewerIdentity, { actor: 'human:current-user' }, session());
  for (const value of ['Verified reviewer account', 'Signed in as Current Reviewer (OIDC)', 'https://current.example', 'current-subject']) {
    assert.ok(plain(html).includes(value), value);
  }
  assert.doesNotMatch(html, /prototype|self-asserted|DO-NOT-RENDER/);
  const local = f.render(f.ReviewerIdentity, { actor: 'Typed name' }, { ...session(), mode: 'dev' });
  assert.match(local, /Local \/ unverified reviewer/); assert.match(local, /Typed name/);
  assert.doesNotMatch(local, /Verified reviewer account|Current Reviewer/);
  for (const identity of [session({ authenticated: false }), session({ principal: null }),
    session({ principal: { ...session().principal, verified: 'true' } }),
    session({ principal: { ...session().principal, issuer: '' } }),
    session({ principal: { ...session().principal, source: 'mesh' } })]) {
    const unavailable = f.render(f.ReviewerIdentity, { actor: 'Typed name' }, identity);
    assert.match(unavailable, /Reviewer identity unavailable/);
    assert.doesNotMatch(unavailable, /Verified reviewer account|self-asserted|DO-NOT-RENDER/);
  }
});

async function reviewPanel(t, history, readonly = false) {
  const f = fixture();
  const finding = { id: 'finding', status: 'open', scanner_status: 'open', evidence: 'Observed evidence', review: history };
  const panel = mount((hooks) => {
    if (readonly) {
      const { FindingReviewAccess } = f.load(new URL('./FindingActions.tsx', import.meta.url), {
        react: hooks, '../lib/hooks': { useAsync: () => ({ data: history, loading: false, error: null }) },
        './PermissionGate': { PermissionButton: Mantine.Button, usePermissions: () => ({ can: () => false }) },
      });
      return (props) => { const child = FindingReviewAccess(props); return child.type(child.props); };
    }
    return f.load(new URL('./FindingReviewPanel.tsx', import.meta.url), {
      react: hooks, '../api/client': { api: { finding: async () => finding, findingReview: async () => history }, errorText: (e) => e.message },
      './PermissionGate': { usePermissions: () => ({ can: () => true, reason: () => null }) },
      '../state/AppState': { useAppState: () => ({ actor: 'human:current-user', status: { kill: { engaged: false } } }) },
    }).FindingReviewPanel;
  }, { finding, opened: true, onToggle() {}, onFinding() {} });
  t.after(() => panel.unmount()); await panel.settle();
  if (readonly) {
    panel.find((node) => node.props?.children === 'Show review history').props.onClick(); await panel.settle();
  }
  return f.renderNode(panel.find(() => true), session());
}

for (const readonly of [false, true]) {
  test(`${readonly ? 'read-only' : 'editable'} review history preserves each event's identity independently`, async (t) => {
    const history = summary([
      event({ id: 'old', reviewed_by: 'Original Local', identity_verified: false, reviewed_principal: undefined }),
      event({ id: 'first', reviewed_principal: evidence({ ...secrets }) }),
      event({ id: 'second', reviewed_by: 'human:another-issuer', reviewed_principal: evidence({ iss: 'https://other.example', sub: 'other-subject' }) }),
    ]);
    const html = await reviewPanel(t, history, readonly);
    for (const value of ['Original Local', 'Local / unverified identity', 'https://identity.example', 'https://other.example',
      'rivera-123', 'other-subject', 'Verified at decision (OIDC)', 'Review expired']) {
      if (readonly && value === 'Review expired') continue;
      assert.ok(plain(html).includes(value), value);
    }
    assert.doesNotMatch(html, /DO-NOT-RENDER|self-asserted identity \(unverified\)|This prototype/);
    if (!readonly) assert.match(html, /Verified reviewer account/);
  });
}

test('a verified current session does not relabel a local review or absent current review', async (t) => {
  let html = await reviewPanel(t, summary([event({ reviewed_by: 'Earlier Local', identity_verified: false, reviewed_principal: undefined })]));
  assert.match(html, /Verified reviewer account/); assert.match(html, /Local \/ unverified identity/);
  assert.doesNotMatch(html, /Verified at decision/);
  html = await reviewPanel(t, { ...summary([]), identity_verified: true });
  assert.doesNotMatch(html, /Verified at decision|Reviewed by/);
});

test('ProposalCard shows the saved decision maker, with no current-session or rollback-actor substitution', () => {
  const f = fixture();
  const { ProposalCard } = f.load(new URL('./ProposalCard.tsx', import.meta.url));
  const actions = { approve() {}, deny() {}, apply() {}, rollback() {}, openFinding() {} };
  for (const state of ['approved', 'denied', 'verified', 'rolled_back']) {
    const p = { ...proposal(state, 'decision'), decided_by: 'human:recorded-actor', decided_principal: evidence({ ...secrets }),
      history: [{ state: 'rolled_back', actor: 'Different rollback operator', ts: '2026-11-05T12:00:00Z' }] };
    const html = f.render(ProposalCard, { p, actions }, session());
    assert.match(plain(html), /Decision recorded by ITC Rivera/);
    assert.match(html, /Verified at decision \(OIDC\)/);
    assert.doesNotMatch(html, /Current Reviewer|DO-NOT-RENDER/);
  }
  const local = f.render(ProposalCard, { p: { ...proposal('approved', 'old'), decided_by: 'Legacy Approver', decided_principal: null }, actions }, session());
  assert.match(plain(local), /Decision recorded by Legacy Approver/); assert.match(local, /Local \/ unverified/);
  assert.doesNotMatch(local, /Verified at decision/);
});

test('a standing policy decision or undecided proposal never claims an interactive verified approver', () => {
  const f = fixture();
  const { ProposalCard } = f.load(new URL('./ProposalCard.tsx', import.meta.url));
  const actions = { approve() {}, deny() {}, apply() {}, rollback() {}, openFinding() {} };
  const automatic = f.render(ProposalCard, { p: { ...proposal('approved', 'automatic'), decided_by: 'policy:Local Signer', decided_principal: evidence() }, actions });
  assert.match(automatic, /Standing policy decision; signer verification is not established/);
  assert.doesNotMatch(automatic, /Verified at decision/);
  const undecided = f.render(ProposalCard, { p: { ...proposal('proposed', 'pending'), decided_by: null }, actions }, session());
  assert.doesNotMatch(undecided, /Decision recorded by|Verified at decision|Current Reviewer/);
});
