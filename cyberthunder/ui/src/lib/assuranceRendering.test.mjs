import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MantineProvider } from '@mantine/core';
import ts from 'typescript';

// Render real components with isolated test fixtures; no browser, server or persisted data.
const sourceRoot = new URL('../', import.meta.url).href;
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier.startsWith('dayjs/plugin/') && !specifier.endsWith('.js')) return nextResolve(`${specifier}.js`, context);
    if (context.parentURL?.startsWith(sourceRoot) && specifier.startsWith('.')) {
      const target = new URL(specifier, context.parentURL);
      for (const extension of ['.ts', '.tsx']) {
        const candidate = new URL(`${target.href}${extension}`);
        if (existsSync(fileURLToPath(candidate))) return { url: candidate.href, shortCircuit: true };
      }
    }
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (url.startsWith(sourceRoot) && /\.tsx?$/.test(url)) {
      const { outputText } = ts.transpileModule(readFileSync(fileURLToPath(url), 'utf8'), {
        fileName: fileURLToPath(url),
        compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020, jsx: ts.JsxEmit.ReactJSX },
      });
      return { format: 'module', source: outputText, shortCircuit: true };
    }
    return nextLoad(url, context);
  },
});
const { ProposalCard } = await import('../components/ProposalCard.tsx');
const { ConfidenceBadge, ReviewBadge } = await import('../components/FindingAssurance.tsx');
const { AppStateProvider } = await import('../state/AppState.tsx');
Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: { getItem: () => '' } });
const render = (component, props) => renderToStaticMarkup(createElement(MantineProvider, {}, createElement(AppStateProvider, {}, createElement(component, props))));
const review = { active: true, suppressed: true, disposition: 'false_positive', current: { reason: 'Reviewed test baseline' } };
const proposal = { id: 'test-proposal', finding_id: 'test-finding', title: 'Test finding', host: 'fixture', severity: 'medium',
  state: 'approved', created_at: '2026-11-05T12:00:00Z', history: [], citations: [], fix_ref: 'test:fix', finding: { review }, fix: null };
const actions = { approve() {}, deny() {}, apply() {}, rollback() {}, openFinding() {} };
const button = (html, label) => [...html.matchAll(/<button\b[^>]*>[\s\S]*?<\/button>/g)].map((m) => m[0]).find((b) => b.includes(`>${label}<`));

test('missing assurance fields render Unknown and Unreviewed without crashing', () => {
  assert.match(render(ConfidenceBadge, {}), /Unknown/);
  assert.match(render(ReviewBadge, {}), /Unreviewed/);
});

test('active review disables Apply and displays its reason', () => {
  const html = render(ProposalCard, { p: proposal, actions });
  assert.match(button(html, 'Apply'), /\sdisabled(?:=|\s|>)/);
  assert.match(html, /Reviewed test baseline/);
  assert.match(html, /Apply blocked by human review/);
});

test('expired/reopened or absent review does not disable Apply', () => {
  for (const finding of [{ review: { ...review, active: false } }, {}]) {
    const html = render(ProposalCard, { p: { ...proposal, finding }, actions });
    assert.ok(button(html, 'Apply'));
    assert.doesNotMatch(button(html, 'Apply'), /\sdisabled(?:=|\s|>)/);
  }
});

test('active suppression preserves Rollback on applied and verified proposals', () => {
  for (const state of ['applied', 'verified']) {
    const html = render(ProposalCard, { p: { ...proposal, state }, actions });
    assert.ok(button(html, 'Rollback'));
    assert.doesNotMatch(button(html, 'Rollback'), /\sdisabled(?:=|\s|>)/);
  }
});
