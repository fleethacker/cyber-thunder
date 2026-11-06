// Explicit loopback browser fixture; all identity and artifact responses are intercepted.
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';
import react from '@vitejs/plugin-react';

const { chromium } = await import(process.env.CT_PLAYWRIGHT_MODULE || 'playwright-core');
const server = await createServer({ root: fileURLToPath(new URL('../../', import.meta.url)), configFile: false,
  cacheDir: fileURLToPath(new URL('../../../../.build/identity-review-vite', import.meta.url)),
  server: { host: '127.0.0.1', port: 0 }, plugins: [react(), {
    name: 'identity-isolation-fixture',
    configureServer(vite) {
      vite.middlewares.use('/identity-fixture.html', async (_req, res) => {
        const html = await vite.transformIndexHtml('/identity-fixture.html', `<!doctype html><html><head><title>Account isolation fixture</title></head><body><div id="root"></div>
          <script type="module">
            import React, {useState, useEffect} from 'react';
            import {createRoot} from 'react-dom/client';
            import {MantineProvider} from '@mantine/core';
            import '@mantine/core/styles.css';
            import {IdentityBoundary, useIdentity} from '/src/state/Identity.tsx';
            import {useAsync} from '/src/lib/hooks.ts';
            import {api} from '/src/api/client.ts';
            import {sessionIdentity} from '/src/api/identity.ts';
            window.currentIdentity = sessionIdentity;
            window.mounts = 0; window.unmounts = 0;
            function PrivateContent() {
              const {identity} = useIdentity();
              const [draft, setDraft] = useState('');
              const report = useAsync(() => api.reportText('/reports/commander'));
              useEffect(() => {window.mounts++; return () => {window.unmounts++;};}, []);
              return React.createElement('section', {'data-account':identity.principal.subject},
                React.createElement('input', {'aria-label':'Private draft', value:draft, onChange:e=>setDraft(e.target.value)}),
                React.createElement('output', {}, report.data || 'Loading private report'),
                React.createElement('button', {onClick:report.reload}, 'Reload report'));
            }
            createRoot(document.getElementById('root')).render(React.createElement(MantineProvider, {},
              React.createElement(IdentityBoundary, {}, React.createElement(PrivateContent))));
          </script></body></html>`);
        res.setHeader('Content-Type', 'text/html'); res.end(html);
      });
    },
  }] });

let browser;
try {
  await server.listen();
  browser = await chromium.launch({ executablePath: process.env.CT_PERMISSION_BROWSER, headless: true });
  const page = await browser.newPage(); page.setDefaultTimeout(15000);
  const errors = []; page.on('pageerror', e => errors.push(e.message));
  await page.route('https://issuer.test/**', route => route.abort());
  await page.addInitScript(() => {
    const interval = window.setInterval;
    window.setInterval = (fn, ms, ...args) => {
      if (ms === 60000) window.pollIdentity = fn;
      return interval(fn, ms, ...args);
    };
  });
  let identity = { mode: 'oidc', authenticated: true, login_available: true, csrf_token: 'session-one', permissions: ['read', 'export'],
    principal: { issuer: 'https://issuer.test', subject: 'one', actor: 'human:one', name: 'One', roles: ['viewer', 'auditor'], source: 'oidc', verified: true } };
  let report = 'FIRST ACCOUNT PRIVATE REPORT', holdReport = false, oldReport;
  await page.route('**/auth/status', route => route.fulfill({ json: identity }));
  await page.route('**/api/v1/reports/commander', route => {
    if (holdReport) { holdReport = false; oldReport = route; return; }
    return route.fulfill({ contentType: 'text/plain', body: report });
  });
  await page.goto(`${server.resolvedUrls.local[0]}identity-fixture.html`);
  await page.getByText(report, { exact: true }).waitFor();
  await page.getByRole('textbox', { name: 'Private draft' }).fill('FIRST ACCOUNT DRAFT');
  identity = { ...identity, permissions: ['export', 'read'], principal: { ...identity.principal, roles: ['auditor', 'viewer'], name: 'Changed display name' } };
  await page.evaluate(() => window.pollIdentity());
  await page.waitForFunction(() => window.currentIdentity().principal.name === 'Changed display name');
  assert.equal(await page.getByRole('textbox', { name: 'Private draft' }).inputValue(), 'FIRST ACCOUNT DRAFT');
  assert.equal(await page.evaluate(() => window.mounts), 1);
  holdReport = true; await page.getByRole('button', { name: 'Reload report' }).click();
  identity = { ...identity, csrf_token: 'session-two', principal: { ...identity.principal, subject: 'two', actor: 'human:two' } };
  report = 'SECOND ACCOUNT REPORT';
  await page.evaluate(() => window.pollIdentity());
  await page.getByText(report, { exact: true }).waitFor();
  assert.equal(await page.getByRole('textbox', { name: 'Private draft' }).inputValue(), '');
  assert.equal(await page.evaluate(() => window.mounts), 2);
  assert.equal(await page.evaluate(() => window.unmounts), 1);
  assert.ok(oldReport);
  await oldReport.fulfill({ contentType: 'text/plain', body: 'LATE FIRST ACCOUNT PRIVATE REPORT' });
  await page.evaluate(() => new Promise(resolve => setTimeout(resolve, 100)));
  assert.equal(await page.locator('output').innerText(), report);
  assert.equal(await page.getByText('FIRST ACCOUNT PRIVATE REPORT', { exact: false }).count(), 0);
  assert.ok(page.url().endsWith('/identity-fixture.html'));
  for (const patch of [{ csrf_token: 'session-three' }, { permissions: ['read'] },
    { principal: { ...identity.principal, roles: ['viewer'] } }, { mode: 'mesh' }]) {
    const before = await page.evaluate(() => window.mounts);
    await page.getByRole('textbox', { name: 'Private draft' }).fill('authority-specific draft');
    identity = { ...identity, ...patch };
    await page.evaluate(() => window.pollIdentity());
    await page.waitForFunction(value => window.mounts === value, before + 1);
    assert.equal(await page.getByRole('textbox', { name: 'Private draft' }).inputValue(), '');
  }
  assert.deepEqual(errors, []);
  console.log('Identity browser acceptance passed: actual cached report/draft reset on account, session, role, permission and mode changes; identical polls preserve state; late old report ignored; no step-up dependency.');
} finally { await browser?.close(); await server.close(); }
