import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MantineProvider } from '@mantine/core';
import ts from 'typescript';

// Render the real widgets and escaped code blocks with in-memory fixtures, as in assuranceRendering.
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
        fileName: fileURLToPath(url), compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020, jsx: ts.JsxEmit.ReactJSX },
      });
      return { format: 'module', source: outputText, shortCircuit: true };
    }
    return nextLoad(url, context);
  },
});
const { ProposalPlanView } = await import('./ProposalPlan.tsx');
const { ProposalCard } = await import('./ProposalCard.tsx');
const { AppStateProvider } = await import('../state/AppState.tsx');
const { IdentityProvider } = await import('../state/Identity.tsx');
const DevAppStateProvider = ({ children }) => createElement(IdentityProvider, {
  identity: { mode: 'dev', authenticated: false, login_available: false, permissions: [] }, logout: async () => {},
}, createElement(AppStateProvider, {}, children));
const { PermissionProvider } = await import('./PermissionGate.tsx');
Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: { getItem: () => 'IT1 Reviewer' } });
const render = (component, props) => renderToStaticMarkup(createElement(MantineProvider, {}, createElement(DevAppStateProvider, {}, createElement(PermissionProvider, { can: () => true }, createElement(component, props)))));
const plan = {
  version: 1, mode: 'static', generated_at: '2026-11-05T12:34:56Z', proposal_id: 'fixture-proposal', proposal_state: 'approved',
  target: { id: 'fixture-target', name: 'Fixture host', asset_type: 'linux', simulated: true, in_scope: true },
  fix: { fix_ref: 'fixture:fix', title: 'Fixture change', asset_type: 'linux', applies_to: ['fixture:rule'], kind: 'script',
    payload: '# exact payload\n<script>alert("payload")</script>\n<img src=x onerror=alert(1)> & <host>\n',
    steps: ['First <manual> step', 'Second step\n  with indentation'], disruption: 'high', reboot: true,
    restarts_services: ['fixture-service'], reversible: true, rollback_kind: 'restore_files', rollback_steps: ['restore <snapshot>'],
    before_state: { files: ['/fixture/file'], dirs: [{ dir: '/fixture/conf', pattern: '*.conf' }],
      commands: { snapshot: 'cat /fixture/file && echo "<capture>"' }, path_modes: 'stat /fixture/mode', path_root: '/fixture', services: ['fixture-service'] },
    verify: { rule_ids: ['fixture:rule'], commands: { health: 'check <fixture>' } }, citations: ['fixture:citation'], source: 'fixture library',
    patch: false, notes: 'Fixture operator note', preview: 'SHORTENED PREVIEW MUST NOT SUBSTITUTE FOR PAYLOAD', rollback_plan: 'Restore the captured fixture', risk_tags: ['access loss'],
  },
  fix_sha256: 'a'.repeat(64), approved_fix_sha256: null,
  checks: [ { code: 'fix_present', status: 'pass', detail: 'Library entry found' },
    { code: 'approval_binding', status: 'blocked', detail: 'Approval differs from the current fix' },
    { code: 'host_validation', status: 'unknown', detail: 'Host has not been checked' } ],
  limitations: ['A fixture limitation'],
};
const buttons = (html) => [...html.matchAll(/<button\b[^>]*>[\s\S]*?<\/button>/g)].map((m) => m[0]);
const button = (html, name) => buttons(html).find((item) => item.includes(`>${name}<`));

test('preview renders exact payload as escaped text and contains no approve/apply controls', () => {
  const html = render(ProposalPlanView, { plan });
  assert.match(html, /# exact payload\n&lt;script&gt;alert\(&quot;payload&quot;\)&lt;\/script&gt;\n&lt;img src=x onerror=alert\(1\)&gt; &amp; &lt;host&gt;\n/);
  assert.doesNotMatch(html, /<script\b|<img\b|SHORTENED PREVIEW/);
  assert.match(html, /First &lt;manual&gt; step/);
  assert.match(html, /Second step\n  with indentation/);
  assert.match(html, /restore &lt;snapshot&gt;/);
  assert.equal(button(html, 'Approve'), undefined);
  assert.equal(button(html, 'Apply'), undefined);
});

test('preview shows capture, verification, disruption, rollback, checks, timestamp and static limitations', () => {
  const html = render(ProposalPlanView, { plan });
  for (const text of ['Fixture host', 'fixture-target', 'fixture-proposal', 'Simulated target', 'In scope',
    '/fixture/file', '/fixture/conf', '*.conf', 'snapshot', 'stat /fixture/mode', 'fixture-service', 'fixture:rule',
    'required by library', 'high', 'Restore the captured fixture', 'Library entry found', 'Approval differs from the current fix',
    'Host has not been checked', 'pass', 'blocked', 'unknown', 'A fixture limitation', 'Static library metadata',
    'No target connection', 'no host validation or guarantee of safety', 'not a complete list of touched files',
    'nothing has been captured', 'none have run', 'technical details']) {
    assert.ok(html.toLowerCase().includes(text.toLowerCase()), `Missing ${text}`);
  }
  assert.match(html, /datetime="2026-11-05T12:34:56Z"/i);
  assert.match(html, /UTC[+-]\d{2}:\d{2}/);
  assert.doesNotMatch(html, /successful dry.run/i);
});

test('empty metadata is explicit and is never a claim of no impact', () => {
  const empty = { ...plan, checks: [], limitations: [], fix: { ...plan.fix, payload: '', steps: [], before_state: {}, verify: {},
    restarts_services: [], reboot: false, rollback_kind: '', rollback_plan: '', rollback_steps: [], risk_tags: [], notes: '' } };
  const html = render(ProposalPlanView, { plan: empty });
  for (const text of ['No payload declared.', 'No steps declared.', 'No file capture paths declared.', 'No directory capture patterns declared.',
    'No capture commands declared.', 'No other capture metadata declared.', 'No verification instructions declared.', 'No service restarts declared.',
    'not declared as required', 'No rollback method declared', 'No rollback plan declared.', 'No rollback steps declared.',
    'No risk tags declared.', 'No notes declared.', 'No static checks provided.', 'No additional limitations supplied.']) {
    assert.ok(html.includes(text), `Missing ${text}`);
  }
  assert.doesNotMatch(html, /no service restart<|no reboot</i);
});

test('missing target metadata remains unknown rather than being inferred as false', () => {
  const html = render(ProposalPlanView, { plan: { ...plan, target: { id: 'missing-host', name: null, asset_type: null, simulated: null, in_scope: null } } });
  for (const text of ['missing-host', 'Unknown target type', 'Simulation unknown', 'Scope unknown']) assert.ok(html.includes(text));
  assert.doesNotMatch(html, /Not simulated|Out of scope/);
  const known = render(ProposalPlanView, { plan: { ...plan, target: { ...plan.target, simulated: false, in_scope: false } } });
  assert.match(known, /Not simulated/); assert.match(known, /Out of scope/);
  assert.doesNotMatch(known, /Simulation unknown|Scope unknown/);
});

test('preview is available on every card state and existing state actions remain available', () => {
  const actions = { approve() {}, deny() {}, apply() {}, rollback() {}, verify() {}, openFinding() {} };
  const proposal = { id: 'fixture-proposal', finding_id: 'fixture-finding', title: 'Fixture finding', host: 'fixture', severity: 'medium',
    state: 'approved', created_at: plan.generated_at, history: [], citations: [], fix_ref: 'fixture:fix', finding: {}, fix: null };
  for (const state of ['proposed', 'approved', 'denied', 'cancelled', 'applying', 'applied', 'verified', 'failed', 'rolled_back']) {
    const html = render(ProposalCard, { p: { ...proposal, state }, actions });
    assert.ok(button(html, 'Preview change'), `Preview on ${state}`);
    assert.doesNotMatch(button(html, 'Preview change'), /\sdisabled(?:=|\s|>)/);
    for (const action of state === 'proposed' ? ['Approve', 'Deny'] : state === 'approved' ? ['Apply'] : ['applied', 'verified'].includes(state) ? ['Rollback'] : []) {
      assert.ok(button(html, action)); assert.doesNotMatch(button(html, action), /\sdisabled(?:=|\s|>)/);
    }
  }
  const busy = render(ProposalCard, { p: proposal, actions, busy: true });
  assert.match(button(busy, 'Preview change'), /\sdisabled(?:=|\s|>)/);
});
