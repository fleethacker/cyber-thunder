import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import test from 'node:test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createModuleLoader } from '../lib/moduleTestSupport.mjs';

const require = createRequire(import.meta.url);
const { MantineProvider } = require('@mantine/core');
const { StaticRouter } = require('react-router-dom');
const h = React.createElement;
const fullStatus = () => ({
  product: 'Cyber Thunder', version: 'fixture', node: 'Local fixture', global_details: true,
  kill: { engaged: false, by: null, reason: null, at: null, via: null },
  audit: { count: 42, head: 'abcdef0123456789', verified: true, detail: 'OK' },
  policy: { enabled: false, signed_by: null, rules: 0 }, adapters: ['ssh'], targets: 8, fixes: 3, demo: false,
  llm: { backend: 'local', model: 'fixture', available: true, queue: 0 },
  link: { mode: 'production', connected: true, offline_override: false, test_connected: false,
    reachability: 'reachable', observed_kbps: 64, kbps: null, latency_ms: null, last_observation: null,
    observations: [], probe_enabled: false, probe_until: null, probe_endpoint: '' },
  outbox: { pending: 0 },
});
const restrictedStatus = () => ({ ...fullStatus(), node: 'Restricted node', global_details: false, targets: 2,
  audit: { count: null, head: null, verified: null, detail: 'Global audit access is required' },
  policy: { enabled: null, signed_by: null, rules: null }, llm: null, link: null, outbox: { pending: null },
});
const identity = { mode: 'oidc', authenticated: true, login_available: true, permissions: ['read'],
  principal: { actor: 'operator-1', name: 'Scoped Operator', roles: ['reader'], kind: 'human' } };
const verified = { ok: true, count: 42, head: 'abcdef0123456789', bad_seq: null, reason: null };

function fixture(status, { verify = null, forbidGlobalControls = false, session = identity } = {}) {
  const load = createModuleLoader();
  load(new URL('../lib/format.ts', import.meta.url), Object.fromEntries(
    ['dayjs', 'dayjs/plugin/relativeTime'].map((name) => [name, { default: require(name) }])));
  const { IdentityProvider } = load(new URL('../state/Identity.tsx', import.meta.url));
  const context = { status, verify, stream: 'open', actor: 'Scoped Operator', setActor() {} };
  const appState = { useAppState: () => context };
  const headers = load(new URL('./HeaderBadges.tsx', import.meta.url), { '../state/AppState': appState });
  const snapshot = { open: { high: 3, medium: 2, low: 1 }, intrusions: 1, verifiedToday: 0, pending: 2, at: '2026-11-05T12:00:00Z' };
  const { default: Commander } = load(new URL('../pages/Commander.tsx', import.meta.url), {
    dayjs: { default: require('dayjs') }, '../state/AppState': appState,
    '../lib/hooks': { useAsync: () => ({ data: snapshot, error: null, reload() {} }), useInterval() {} },
  });
  const globalControl = (name) => () => {
    assert.equal(forbidGlobalControls, false, `${name} mounted with unavailable node details`);
    return h('p', {}, `${name} mounted`);
  };
  const { default: Settings } = load(new URL('../pages/Settings.tsx', import.meta.url), {
    '../state/AppState': appState,
    '../components/PolicyEditor': { PolicyEditor: globalControl('Policy editor') },
    '../components/LinkControls': { LinkControls: globalControl('Link controls') },
    '../lib/hooks': { useAsync: () => {
      assert.equal(forbidGlobalControls, false, 'Demo controls mounted for a restricted account');
      return { data: { available: false }, error: null, reload() {} };
    } },
  });
  const render = (component) => renderToStaticMarkup(h(MantineProvider, {},
    h(StaticRouter, { location: '/settings' }, h(IdentityProvider, { identity: session, logout: async () => {} }, h(component)))));
  return { context, headers: () => render(() => h(React.Fragment, {},
    h(headers.ChainBadge), h(headers.LinkBadge), h(headers.ModelBadge))),
    commander: () => render(Commander), settings: () => render(Settings) };
}

const visible = (html) => html.replace(/<style\b[^>]*>[\s\S]*?<\/style>/g, '').replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ');

test('sanitized status renders restricted badges without inventing zero, offline, or model failure', () => {
  const html = fixture(restrictedStatus()).headers();
  assert.match(html, /Chain: restricted/);
  assert.match(html, /Link and queue: restricted/);
  assert.match(html, /Model: restricted/);
  assert.doesNotMatch(visible(html), /\b0\b|offline|fallback|verified|checking|TAMPERED/i);
});

test('restricted flag hides cached verification and stale global values across header, Commander and Settings', () => {
  const status = { ...fullStatus(), global_details: false, targets: 2 };
  status.llm.model = 'SECRET-MODEL';
  const view = fixture(status, { verify: { ...verified, head: 'SECRET-HEAD' }, forbidGlobalControls: true });
  for (const html of [view.headers(), view.commander(), view.settings()]) {
    assert.doesNotMatch(html, /SECRET-|42 records|64 kbps|0 queued|Policy editor mounted|Link controls mounted/);
  }
});

test('missing global fields without a restriction flag render unknown instead of zero or offline', () => {
  const status = restrictedStatus();
  delete status.global_details;
  const view = fixture(status);
  const header = view.headers();
  assert.match(header, /Chain: unknown/);
  assert.match(header, /Link: unknown/);
  assert.match(header, /Model: unknown/);
  const commander = view.commander();
  for (const text of ['Record count unknown', 'Head unknown', 'Reachability unknown', 'Queue count unknown']) assert.ok(commander.includes(text), text);
  assert.doesNotMatch(visible(commander), /0 records|0 reports queued|offline|tampered|checking/i);
  const settings = view.settings();
  assert.match(settings, /Model status is unknown/);
  assert.match(settings, /Node status did not report these details/);
  assert.doesNotMatch(settings, /Policy editor mounted|Link controls mounted|fallback: template/);
});

test('unknown queue remains unknown when link is available, while an actual zero is displayed', () => {
  const status = fullStatus();
  status.outbox.pending = null;
  const view = fixture(status);
  assert.match(view.headers(), /queue unknown/);
  assert.match(view.commander(), /Queue count unknown/);
  status.outbox.pending = 0;
  assert.match(view.headers(), /0 queued/);
  assert.match(view.commander(), /0 reports queued for sync/);
});

test('restricted Commander keeps scoped counts and kill switch visible', () => {
  const status = restrictedStatus();
  status.kill.engaged = true;
  const text = visible(fixture(status).commander());
  assert.match(text, /Counts cover only assets visible to your account \(2 inventory assets\)/);
  assert.match(text, /Open CAT I 3/);
  assert.match(text, /Decisions pending 2/);
  assert.match(text, /Record count restricted/);
  assert.match(text, /Head restricted/);
  assert.match(text, /Link restricted/);
  assert.match(text, /Queue count restricted/);
  assert.match(text, /Kill switch engaged/);
  assert.doesNotMatch(text, /0 records|0 reports queued|offline|tampered/i);
});

test('restricted Settings preserves signed-in account and navigation without mounting node configuration', () => {
  const html = fixture(restrictedStatus(), { forbidGlobalControls: true }).settings();
  for (const text of ['Signed-in account', 'Scoped Operator', 'Roles: reader', 'Model status is restricted',
    'Standing approval policy', 'Link observations and controls', 'Demonstration controls']) assert.ok(html.includes(text), text);
  assert.match(html, /<button\b[^>]*>[\s\S]*?Sign out/);
  assert.match(html, /href="\/content"/);
  assert.doesNotMatch(html, /Policy editor mounted|Link controls mounted|fallback: template|Loading|not loaded|not part of this build/);
});

test('Settings waits for node details before mounting global controls during initial load or unavailable status', () => {
  const view = fixture(null, { forbidGlobalControls: true });
  const html = view.settings();
  assert.match(html, /Model status is unknown/);
  assert.match(html, /Node status did not report these details/);
  assert.match(html, /Sign out/);
  assert.doesNotMatch(html, /Policy editor mounted|Link controls mounted/);
  for (const text of ['Chain: unknown', 'Link: unknown', 'Model: unknown']) assert.ok(view.headers().includes(text), text);
});

test('full and legacy local fixtures preserve known audit, model, link, queue and Settings behavior', () => {
  for (const legacy of [false, true]) {
    const status = fullStatus();
    if (legacy) delete status.global_details;
    const view = fixture(status, { verify: verified, session: { mode: 'dev', authenticated: false, login_available: false, permissions: [] } });
    const header = visible(view.headers());
    assert.match(header, /Chain verified · 42 records/);
    assert.match(header, /Endpoint observed reachable · 0 queued/);
    assert.match(header, /local\/fixture · available/);
    assert.match(view.commander(), /42 records/);
    const settings = view.settings();
    assert.match(settings, /Local test identity \(unverified\)/);
    assert.match(settings, /Policy editor mounted/);
    assert.match(settings, /Link controls mounted/);
    assert.match(settings, /The simulated range is not part of this build/);
    assert.doesNotMatch(settings, /Model status is unknown|Node-wide details are not available/);
  }
});

test('known negative states retain tamper, operator-offline and model-fallback warnings', () => {
  const status = fullStatus();
  status.llm.available = false;
  Object.assign(status.link, { connected: false, offline_override: true });
  const view = fixture(status, { verify: { ...verified, ok: false, bad_seq: 7, reason: 'Mismatch' } });
  const html = view.headers();
  assert.match(html, /TAMPERED at #7/);
  assert.match(html, /Operator offline/);
  assert.match(html, /local\/fixture · fallback/);
  assert.match(view.commander(), /tampered at #7/);
  assert.match(view.settings(), /fallback: template/);
});
