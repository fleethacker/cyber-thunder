import assert from 'node:assert/strict';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { createModuleLoader } from '../lib/moduleTestSupport.mjs';
import { mount } from '../lib/rollbackTestSupport.mjs';

const record = (seq, subject, details = {}) => ({ seq, subject, details, action: 'remediation.before_state', outcome: 'ok' });
function fixture() {
  const requests = [], renders = [];
  let listener;
  const panel = mount((hooks) => {
    const { useProposalAudit } = createModuleLoader()(new URL('./ApplyTimeline.tsx', import.meta.url), {
      react: hooks,
      '../lib/format': { fmtClock: (ts) => ts },
      '../state/AppState': { useAuditListener: (fn) => { listener = fn; } },
      '../api/client': { api: { audit: (query) => new Promise((resolve, reject) => requests.push({ query, resolve, reject })) } },
    });
    return ({ id }) => { renders.push(useProposalAudit(id)); return null; };
  }, { id: 'first' });
  return { ...panel, requests, renders, current: () => renders.at(-1), send: (r) => listener(r) };
}

test('fetched and streamed audit records are filtered to the exact proposal', async () => {
  const panel = fixture(); await panel.settle();
  assert.deepEqual(panel.requests[0].query, { subject: 'first', limit: 1000 });
  panel.requests[0].resolve({ records: [record(1, 'first'), record(2, 'second'), record(3, 'second', { proposal_id: 'first' })] });
  await panel.settle();
  panel.send(record(4, 'second'));
  panel.send(record(5, null, { proposal_id: 'first' }));
  await panel.settle();
  assert.deepEqual(panel.current().map((r) => r.seq), [1, 5]);
  panel.unmount();
});

test('a slower fetch preserves streamed evidence and deduplicates audit sequence numbers', async () => {
  const panel = fixture(); await panel.settle();
  panel.send(record(4, 'first')); await panel.settle();
  panel.requests[0].resolve({ records: [record(2, 'first'), record(4, 'first')] });
  await panel.settle();
  panel.send(record(4, 'first')); await panel.settle();
  assert.deepEqual(panel.current().map((r) => r.seq), [2, 4]);
  panel.unmount();
});

test('proposal switch hides cached records even before effects, including an unavailable next audit', async () => {
  const panel = fixture(); await panel.settle();
  panel.requests[0].resolve({ records: [record(1, 'first')] }); await panel.settle();
  assert.equal(panel.current().length, 1);
  const start = panel.renders.length;
  await panel.rerender({ id: 'second' });
  assert.ok(panel.renders.slice(start).every((records) => records.length === 0));
  panel.requests[1].reject(new Error('Audit unavailable')); await panel.settle();
  panel.send(record(2, 'first')); await panel.settle();
  assert.deepEqual(panel.current(), []);
  panel.unmount();
});

test('a late response for a previous proposal cannot replace the current proposal audit', async () => {
  const panel = fixture(); await panel.settle();
  await panel.rerender({ id: 'second' });
  panel.requests[1].resolve({ records: [record(2, 'second')] }); await panel.settle();
  panel.requests[0].resolve({ records: [record(1, 'first')] }); await panel.settle();
  assert.deepEqual(panel.current().map((r) => r.subject), ['second']);
  panel.unmount();
});

test('malformed live records are ignored while valid fetched evidence remains usable', async () => {
  const panel = fixture(); await panel.settle();
  panel.requests[0].resolve({ records: [record(1, 'first')] }); await panel.settle();
  for (const value of [null, false, {}, { ...record(2, 'first'), seq: '2' },
    record(3, 'first', { proposal_id: 'second' })]) panel.send(value);
  await panel.settle();
  assert.deepEqual(panel.current().map(r => r.seq), [1]);
  panel.unmount();
});

test('fetch and stream conflicts stay quarantined instead of choosing a successful receipt', async () => {
  const panel = fixture(); await panel.settle();
  panel.send(record(4, 'first')); await panel.settle();
  panel.requests[0].resolve({ records: [{ ...record(4, 'first'), outcome: 'error' }] });
  await panel.settle();
  assert.deepEqual(panel.current(), []);
  panel.send(record(4, 'first')); await panel.settle();
  assert.deepEqual(panel.current(), []);
  panel.unmount();
});

// Explicit offline browser check. Bundle in memory; intercept fetch/EventSource and
// deny every browser request. The real providers, hooks, rendering and clicks run.
test('real account boundary clears timeline audit on switch and revocation for the same proposal', {
  skip: !process.env.CT_PLAYWRIGHT_MODULE || !process.env.CT_TIMELINE_BUNDLER_MODULE,
}, async (t) => {
  const { chromium } = await import(process.env.CT_PLAYWRIGHT_MODULE);
  const { build } = await import(process.env.CT_TIMELINE_BUNDLER_MODULE);
  const bundle = await build({ bundle: true, write: false, format: 'iife', platform: 'browser', jsx: 'automatic',
    define: { 'process.env.NODE_ENV': '"production"' },
    stdin: { resolveDir: fileURLToPath(new URL('../../', import.meta.url)), loader: 'tsx', contents: `
      import React, {useState} from 'react';
      import {createRoot} from 'react-dom/client';
      import {MantineProvider} from '@mantine/core';
      import {IdentityBoundary, useIdentity} from './src/state/Identity';
      import {AppStateProvider} from './src/state/AppState';
      import {ApplyTimeline} from './src/components/ApplyTimeline';
      window.identity = {mode:'oidc', authenticated:true, login_available:true, permissions:['read','audit'],
        principal:{issuer:'fixture', subject:'one', actor:'human:one', name:'One', roles:['auditor']}};
      window.auditRequests = []; window.streams = []; window.calls = [];
      window.fetch = async (url, options = {}) => {
        window.calls.push([url, options.method || 'GET']);
        if (url === '/auth/status') return Response.json(window.identity);
        if (url === '/api/v1/status') return Response.json({});
        if (url === '/api/v1/audit/verify') return Response.json({ok:true, count:0});
        if (url.startsWith('/api/v1/audit?')) {
          if (!window.identity.permissions.includes('audit')) return Response.json({detail:'Denied'}, {status:403});
          return new Promise(resolve => window.auditRequests.push({url,
            resolve: records => resolve(Response.json({records}))}));
        }
        throw new Error('Unexpected fixture request: ' + url);
      };
      window.EventSource = class {
        callbacks = {}; closed = false;
        constructor() { window.streams.push(this); }
        addEventListener(type, fn) { this.callbacks[type] = fn; }
        close() { this.closed = true; }
      };
      const interval = window.setInterval;
      window.setInterval = (fn, ms, ...args) => {
        if (ms === 60000) window.pollIdentity = fn;
        return interval(fn, ms, ...args);
      };
      function Content() {
        const {identity} = useIdentity();
        const [id, setId] = useState('first');
        return <section data-account={identity.principal.subject}>
          <button onClick={() => setId(id === 'first' ? 'second' : 'first')}>Switch proposal</button>
          <button onClick={() => window.pollIdentity()}>Refresh account</button>
          <ApplyTimeline proposal={{id, state:'failed', history:[], host:'fixture-host', finding_id:'fixture-finding'}} />
        </section>;
      }
      window.root = createRoot(document.getElementById('root'));
      window.root.render(<MantineProvider><IdentityBoundary><AppStateProvider><Content /></AppStateProvider></IdentityBoundary></MantineProvider>);
    ` } });
  const browser = await chromium.launch({ executablePath: process.env.CT_PERMISSION_BROWSER, headless: true,
    args: ['--disable-background-networking'] });
  t.after(() => browser.close());
  const page = await browser.newPage();
  page.setDefaultTimeout(15000);
  const errors = [], network = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', route => { network.push(route.request().url()); return route.abort(); });
  await page.setContent('<html><body><div id="root"></div></body></html>');
  await page.addScriptTag({ content: bundle.outputFiles[0].text });
  const waitRequests = async count => {
    try { await page.waitForFunction(n => window.auditRequests.length === n, count); }
    catch (error) {
      t.diagnostic(JSON.stringify({ errors, state: await page.evaluate(() => ({
        body: document.body.innerText, calls: window.calls, requests: window.auditRequests.length,
      })) }));
      throw error;
    }
  };
  const resolve = (index, records) => page.evaluate(({index, records}) => window.auditRequests[index].resolve(records), {index, records});
  const send = (index, value) => page.evaluate(({index, value}) => window.streams[index].callbacks.audit({data: JSON.stringify(value)}), {index, value});
  const failure = (seq, subject, note) => ({seq, subject, action:'proposal.failed', outcome:'failed', details:{note}});
  const body = () => page.locator('body').innerText();
  await waitRequests(1);
  await page.waitForFunction(() => window.streams.length === 1);
  await send(0, record(5, 'first'));
  await page.getByText('Before-state captured', {exact:true}).waitFor();
  await resolve(0, [failure(2, 'first', 'FIRST ACCOUNT AUDIT'), record(5, 'first')]);
  await page.getByText('FIRST ACCOUNT AUDIT', {exact:true}).waitFor();
  await page.getByRole('button', {name:'Switch proposal'}).click();
  await waitRequests(2);
  assert.doesNotMatch(await body(), /FIRST ACCOUNT AUDIT|Before-state captured/);
  await page.getByRole('button', {name:'Switch proposal'}).click();
  await waitRequests(3);
  await page.evaluate(() => { window.identity = {...window.identity,
    principal:{...window.identity.principal, subject:'two', actor:'human:two'}}; });
  await page.getByRole('button', {name:'Refresh account'}).click();
  await waitRequests(4);
  await page.locator('[data-account="two"]').waitFor();
  await resolve(1, [failure(20, 'second', 'LATE OTHER PROPOSAL')]);
  await resolve(2, [failure(21, 'first', 'LATE FIRST ACCOUNT')]);
  await send(0, failure(22, 'first', 'STALE FIRST STREAM'));
  await resolve(3, [failure(24, 'first', 'SECOND ACCOUNT AUDIT')]);
  await page.getByText('SECOND ACCOUNT AUDIT', {exact:true}).waitFor();
  assert.doesNotMatch(await body(), /FIRST ACCOUNT|OTHER PROPOSAL|STALE FIRST|Verified ✓/);
  assert.equal(await page.evaluate(() => window.streams[0].closed), true);
  await page.evaluate(() => { window.identity = {...window.identity, permissions:['read']}; });
  await page.getByRole('button', {name:'Refresh account'}).click();
  await page.waitForFunction(() => !document.body.textContent.includes('SECOND ACCOUNT AUDIT'));
  await send(1, failure(25, 'first', 'REVOKED STREAM'));
  assert.doesNotMatch(await body(), /ACCOUNT AUDIT|REVOKED STREAM|Before-state captured|Verified ✓/);
  assert.equal(await page.evaluate(() => window.streams.every(s => s.closed)), true);
  assert.ok((await page.evaluate(() => window.calls)).every(([, method]) => method === 'GET'));
  await page.evaluate(() => window.root.unmount());
  assert.deepEqual(errors, []);
  assert.deepEqual(network, []);
});
