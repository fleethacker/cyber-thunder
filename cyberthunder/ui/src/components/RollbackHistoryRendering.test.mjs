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
import { evaluate, helpers, mount, proposal, ui } from '../lib/rollbackTestSupport.mjs';

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
const { AppStateProvider } = await import('../state/AppState.tsx');
const { default: App } = await import('../App.tsx');
Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: { getItem: () => '' } });
const render = (component, props) => renderToStaticMarkup(createElement(MantineProvider, {}, createElement(AppStateProvider, {}, createElement(StaticRouter, { location: '/audit' }, createElement(component, props)))));
const renderHash = (component, props, hash = '#/audit') => {
  const browser = { location: { hash, origin: 'https://fixture.invalid', href: `https://fixture.invalid/${hash}` }, history: { state: { idx: 0 } }, document: { querySelector: () => null } };
  // HashRouter layout effects cannot run during SSR. Permit only that expected warning.
  const originalError = console.error, warnings = [];
  console.error = (...args) => warnings.push(args);
  try {
    const html = renderToStaticMarkup(createElement(MantineProvider, {}, createElement(AppStateProvider, {}, createElement(HashRouter, { window: browser }, createElement(component, props)))));
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

test('confirmation describes saved state and newer-change risk and blocks gated direct handlers', async () => {
  let confirms = 0;
  const props = { proposal: proposal(), busy: false, blockedReason: null, error: null, onConfirm: () => confirms++, onClose() {} };
  const panel = mount(() => evaluate(new URL('./RollbackConfirmation.tsx', import.meta.url), {
    '@mantine/core': ui, '../lib/format': { fmtZonedTime: (value) => value }, '../lib/proposalHistory': helpers,
    './ProposalDiff': ui, './common': ui,
  }).RollbackConfirmation, props);
  try {
    await panel.settle();
    const text = panel.nodes().map((node) => typeof node.props?.children === 'string' ? node.props.children : '').join(' ');
    for (const phrase of ['may overwrite newer work', 'may restore the original vulnerability', 'does not guarantee a safe or complete restore', 'vary by platform and change type', 'Inspect both the saved state and the live target', 'saved diff does not inspect the live target', 'run a fresh scan']) assert.ok(text.includes(phrase), phrase);
    assert.equal(confirms, 0);
    await panel.click('Confirm rollback');
    assert.equal(confirms, 1);
    for (const change of [{ busy: true }, { busy: false, blockedReason: 'Kill switch engaged' }, { blockedReason: null, proposal: proposal('failed') }]) {
      Object.assign(props, change); await panel.rerender(props);
      assert.equal(panel.button('Confirm rollback').props.disabled, true);
      panel.button('Confirm rollback').props.onClick();
    }
    assert.equal(confirms, 1);
  } finally { panel.unmount(); }
});
