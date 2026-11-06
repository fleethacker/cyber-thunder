import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { HashRouter, StaticRouter } from 'react-router-dom';
import { MantineProvider } from '@mantine/core';
import ts from 'typescript';
import { proposal } from '../lib/rollbackTestSupport.mjs';

const sourceRoot = new URL('../', import.meta.url).href;
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier.startsWith('dayjs/plugin/') && !specifier.endsWith('.js')) return nextResolve(`${specifier}.js`, context);
    if (context.parentURL?.startsWith(sourceRoot) && specifier.startsWith('.')) {
      for (const extension of ['.ts', '.tsx']) {
        const candidate = new URL(`${new URL(specifier, context.parentURL).href}${extension}`);
        if (existsSync(fileURLToPath(candidate))) return { url: candidate.href, shortCircuit: true };
      }
    }
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (url.startsWith(sourceRoot) && /\.tsx?$/.test(url)) {
      const { outputText } = ts.transpileModule(readFileSync(fileURLToPath(url), 'utf8'), {
        fileName: fileURLToPath(url), compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020, jsx: ts.JsxEmit.ReactJSX },
      });
      return { format: 'module', source: outputText, shortCircuit: true };
    }
    return nextLoad(url, context);
  },
});
const { ProposalCard } = await import('./ProposalCard.tsx');
const { AuditSubject } = await import('./AuditSubject.tsx');
const { RollbackGuardView } = await import('./ProposalDiff.tsx');
const { AppStateProvider } = await import('../state/AppState.tsx');
const { IdentityProvider } = await import('../state/Identity.tsx');
const DevAppStateProvider = ({ children }) => createElement(IdentityProvider, {
  identity: { mode: 'dev', authenticated: false, login_available: false, permissions: [] }, logout: async () => {},
}, createElement(AppStateProvider, {}, children));
const { PermissionProvider } = await import('./PermissionGate.tsx');
const { default: App } = await import('../App.tsx');
Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: { getItem: () => '' } });
const render = (component, props) => renderToStaticMarkup(createElement(MantineProvider, {}, createElement(DevAppStateProvider, {}, createElement(StaticRouter, { location: '/audit' }, createElement(PermissionProvider, { can: () => true }, createElement(component, props))))));
const renderHash = (component, props, hash = '#/audit') => {
  const browser = { location: { hash, origin: 'https://fixture.invalid', href: `https://fixture.invalid/${hash}` }, history: { state: { idx: 0 } }, document: { querySelector: () => null } };
  // HashRouter layout effects cannot run during SSR. Permit only that expected warning.
  const originalError = console.error, warnings = [];
  console.error = (...args) => warnings.push(args);
  try {
    const html = renderToStaticMarkup(createElement(MantineProvider, {}, createElement(DevAppStateProvider, {}, createElement(HashRouter, { window: browser }, createElement(PermissionProvider, { can: () => true }, createElement(component, props))))));
    for (const [message] of warnings) assert.match(String(message), /^Warning: useLayoutEffect does nothing on the server/);
    return html;
  } finally { console.error = originalError; }
};
const actions = { approve() {}, deny() {}, apply() {}, rollback() {}, openFinding() {} };
const button = (html, name) => [...html.matchAll(/<button\b[^>]*>[\s\S]*?<\/button>/g)].map((m) => m[0]).find((b) => b.includes(`>${name}<`));

test('old proposal cards show their ID and absolute dates; decision actor is not labeled as rollback actor', () => {
  const html = render(ProposalCard, { p: proposal('rolled_back'), actions });
  assert.match(html, /Proposal old-change/);
  assert.match(html, /Created .*2026-10-28/);
  assert.match(html, /Last activity .*2026-10-29/);
  assert.match(html, /UTC[+-]\d{2}:\d{2}/);
  assert.match(html, /Decision recorded by/);
  assert.doesNotMatch(html, /rolled back by.*IT1 Approver/i);
  assert.match(html, /Earlier passing observations may no longer describe the target/);
});

test('only applied/verified cards expose rollback, and parent actor/kill blocking disables it', () => {
  for (const state of ['applied', 'verified']) {
    const allowed = render(ProposalCard, { p: proposal(state), actions });
    assert.ok(button(allowed, 'Rollback'));
    assert.doesNotMatch(button(allowed, 'Rollback'), /\sdisabled(?:=|\s|>)/);
    const blocked = render(ProposalCard, { p: proposal(state), actions, actionsDisabled: true });
    assert.match(button(blocked, 'Rollback'), /\sdisabled(?:=|\s|>)/);
  }
  for (const state of ['failed', 'rolled_back', 'denied', 'cancelled']) assert.equal(button(render(ProposalCard, { p: proposal(state), actions }), 'Rollback'), undefined);
});

test('audit subjects render real encoded proposal links, while non-proposal subjects remain text', () => {
  const record = { action: 'proposal.verified', subject: 'old/change?&<x>', details: {} };
  const html = renderHash(AuditSubject, { record });
  assert.match(html, /href="#\/\?proposal=old%2Fchange%3F%26%3Cx%3E"/);
  assert.match(html, /aria-label="Open proposal old\/change\?&amp;&lt;x&gt;"/);
  assert.doesNotMatch(render(AuditSubject, { record: { ...record, action: 'target.updated' } }), /<a\b/);
});

test('the emitted hash link opens the actual Decisions route without an alias', () => {
  const html = renderHash(AuditSubject, { record: { action: 'proposal.verified', subject: 'old-change', details: {} } });
  const href = html.match(/href="([^"]+)"/)[1];
  assert.equal(href, '#/?proposal=old-change');
  const destination = renderHash(App, {}, href);
  assert.match(destination, />Decisions<\/h1>/);
  assert.match(destination, /Loading the linked proposal/);
  assert.doesNotMatch(destination, /Page not found/);
});

const guard = (overrides = {}) => ({
  status: 'not_checked', coverage: 'partial', live_checked: false, identity_bound: true,
  transition_allowed: true, conflicting_proposals: [], reasons: [], limitations: ['Service reload effects are not compared.'],
  ...overrides,
});

test('static guard renders actual coverage, reasons, limits and escaped conflict links', () => {
  const html = renderHash(RollbackGuardView, { guard: guard({ status: 'blocked',
    reasons: ['Later apply attempt <script>alert(1)</script>'],
    conflicting_proposals: ['later/change?&<x>'], limitations: ['External <writers> are not locked.'],
  }) });
  for (const text of ['Current static rollback checks', 'Status: blocked', 'Coverage: partial',
    'Only some effects', 'without connecting to the target', 'Later recorded changes on this target block restoration',
    'engine repeats its checks at restore time', 'external drift may remain unknown']) assert.ok(html.includes(text), text);
  assert.match(html, /Later apply attempt &lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(html, /External &lt;writers&gt; are not locked/);
  assert.doesNotMatch(html, /<script\b|>safe</i);
  assert.match(html, /href="#\/\?proposal=later%2Fchange%3F%26%3Cx%3E"/);
});

test('historical preflight is visibly separate from current static blockers and cannot read as current authorization', () => {
  const html = render(RollbackGuardView, { guard: guard({ status: 'blocked', reasons: ['Later proposal changed the target'],
    last_preflight: guard({ status: 'checked_files', coverage: 'files', live_checked: true, checked_at: '2026-11-01T12:00:00Z' }),
  }) });
  for (const text of ['Status: blocked', 'Later proposal changed the target', 'Live comparison reported: not performed',
    'Last preflight (historical)', '2026-11-01', 'checked_files', 'earlier attempt', 'does not authorize a rollback now']) assert.ok(html.includes(text), text);
});

test('unsupported drift coverage and missing identity remain explicit without a safe label', () => {
  const html = render(RollbackGuardView, { guard: guard({ coverage: 'unsupported', identity_bound: false }) });
  for (const text of ['Coverage: unsupported', 'Live platform drift detection is unsupported',
    'may overwrite newer external changes', 'no recorded binding', 'External drift may still be unknown']) assert.ok(html.includes(text), text);
  assert.doesNotMatch(html, />safe<|complete coverage confirmed|no impact/i);
});

test('file coverage names its bounds; missing guard reports unknown and failed lookup retains actual reasons', () => {
  const files = render(RollbackGuardView, { guard: guard({ coverage: 'files' }) });
  assert.match(files, /file bytes, type, mode and ownership/);
  assert.match(files, /does not cover ACLs, extended attributes or unrelated host state/);
  const missing = render(RollbackGuardView, { guard: null });
  assert.match(missing, /Rollback checks are unavailable/);
  assert.match(missing, /Coverage: unknown/);
  assert.doesNotMatch(missing, /No static blockers reported/);
  const failed = render(RollbackGuardView, { guard: { status: 'blocked', coverage: 'unknown', live_checked: false, reasons: ['Persisted inventory is unreadable'] } });
  assert.match(failed, /Persisted inventory is unreadable/);
  assert.match(failed, /Endpoint identity: unknown/);
});
