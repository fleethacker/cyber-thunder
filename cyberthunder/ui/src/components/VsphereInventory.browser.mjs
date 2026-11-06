// Explicit loopback fixture: native Chromium, real Mantine/identity provider, simulated API responses only.
// CT_PLAYWRIGHT_MODULE is a module URL; CT_VSPHERE_BROWSER is a native Chromium executable path.
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';
import react from '@vitejs/plugin-react';

const { chromium } = await import(process.env.CT_PLAYWRIGHT_MODULE || 'playwright-core');
const server = await createServer({
  root: fileURLToPath(new URL('../../', import.meta.url)), configFile: false,
  cacheDir: fileURLToPath(new URL('../../../../.build/vsphere-inventory-vite', import.meta.url)),
  server: { host: '127.0.0.1', port: 0 },
  plugins: [react(), {
    name: 'vsphere-inventory-browser-fixture',
    configureServer(vite) {
      vite.middlewares.use('/vsphere-fixture.html', async (_req, res) => {
        const html = await vite.transformIndexHtml('/vsphere-fixture.html', `<!doctype html><html lang="en"><head><title>Simulated vSphere UI fixture</title></head><body><div id="root"></div>
          <script type="module">
            import React, {useState} from 'react';
            import {createRoot} from 'react-dom/client';
            import {MantineProvider, Button, Text} from '@mantine/core';
            import '@mantine/core/styles.css';
            import {IdentityProvider} from '/src/state/Identity.tsx';
            import {setSessionIdentity} from '/src/api/identity.ts';
            import {VsphereInventory} from '/src/components/VsphereInventory.tsx';
            const target = {id: 'fixture-vc', name: 'Simulated vCenter fixture', environment: 'fixture', authorization_id: 'generation-one',
              asset_type: 'linux', transport: 'vsphere', address: '192.0.2.10', in_scope: true, options: {hypervisor: 'vsphere'}};
            function Fixture() {
              const [account, setAccount] = useState('alice');
              const [opened, setOpened] = useState(true);
              window.fixtureSetAccount = setAccount;
              const identity = {mode: 'oidc', authenticated: true, login_available: false, permissions: ['read'],
                principal: {actor: 'human:' + account, issuer: 'https://fixture.invalid', subject: account,
                  name: account, roles: ['viewer'], source: 'oidc', verified: true}};
              setSessionIdentity(identity);
              return React.createElement(MantineProvider, {}, React.createElement(IdentityProvider, {identity, logout: async () => {}},
                React.createElement(Text, {}, 'Browser fixture: all API responses are simulated; no identity provider or vCenter is contacted.'),
                React.createElement(Button, {onClick: () => setOpened(true)}, 'Open fixture source'),
                React.createElement(VsphereInventory, {target: opened ? target : null, onClose: () => setOpened(false)})));
            }
            createRoot(document.getElementById('root')).render(React.createElement(React.StrictMode, {}, React.createElement(Fixture)));
          </script></body></html>`);
        res.setHeader('Content-Type', 'text/html'); res.end(html);
      });
    },
  }],
});

const rows = account => Array.from({ length: 130 }, (_, index) => ({
  id: `object-${index}`, hostname: `${account}-Inventory-${String(index).padStart(3, '0')}`, address: null,
  facts: { vsphere_kind: index % 2 ? 'HostSystem' : 'VirtualMachine', vsphere_ref: `ref-${index}`,
    power_state: index % 3 ? 'poweredOn' : 'poweredOff', reported_addresses: [`10.20.0.${index + 1}`] },
  evidence: [`${account}-EVIDENCE-${String(index).padStart(3, '0')}`], notes: `${account}-NOTES-${String(index).padStart(3, '0')}`,
}));
const run = (id, account) => ({ version: 1, id, source: 'vsphere', target_id: 'fixture-vc',
  authorization_scope: { version: 1, target_id: 'fixture-vc', environment: 'fixture', authorization_id: 'generation-one' },
  requested_by: `human:${account}`, requested_principal: null, started_at: '2026-11-05T12:00:00Z', finished_at: '2026-11-05T12:01:00Z',
  status: 'finished', complete: true, collection_started: true, observation_count: 130, error: null, observations: rows(account) });
const brief = ({ observations, ...rest }) => rest;
const requests = [], errors = [];
let browser;
try {
  await server.listen();
  const base = server.resolvedUrls.local[0];
  const origin = new URL(base).origin;
  browser = await chromium.launch({ executablePath: process.env.CT_VSPHERE_BROWSER, headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1050 } });
  page.setDefaultTimeout(15000);
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url());
    if (url.origin !== origin) {
      errors.push('Unexpected non-fixture request'); return route.abort();
    }
    if (!url.pathname.startsWith('/api/')) return route.continue();
    const path = url.pathname;
    requests.push({ method: request.method(), path, query: url.search });
    assert.equal(request.method(), 'GET', 'Pagination and filters cannot invoke collection or mutation');
    const account = request.headers()['x-actor'] === 'human:bob' ? 'bob' : 'alice';
    const answer = json => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(json) });
    if (path === '/api/v1/discovery/vsphere/fixture-vc/runs') {
      assert.equal(url.search, '?limit=20');
      return answer(['run-one', 'run-two'].map(id => brief(run(id, account))));
    }
    if (['run-one', 'run-two'].some(id => path === `/api/v1/discovery/vsphere/fixture-vc/runs/${id}`)) {
      return answer(run(path.split('/').at(-1), account));
    }
    assert.fail(`Unexpected fixture API path ${path}`);
  });
  await page.goto(`${base}vsphere-fixture.html`);
  const table = page.getByRole('table', { name: 'vSphere inventory observations', exact: true });
  const bodyRows = () => table.locator('tbody tr');
  const select = (name, option) => page.getByLabel(name, { exact: true }).selectOption(option);
  const keyboard = async (name, key = 'Enter') => {
    await page.getByRole('button', { name, exact: true }).focus(); await page.keyboard.press(key);
  };
  await page.getByRole('button', { name: 'View collection run-one' }).waitFor();
  assert.equal(await page.getByRole('button', { name: 'Collect inventory', exact: true }).isDisabled(), true);
  assert.equal(await table.count(), 0, 'Opening reads history without opening a snapshot or collecting');
  await keyboard('View collection run-one'); await table.waitFor();
  const beforeFilters = requests.length;
  assert.equal(await bodyRows().count(), 25);
  assert.equal(await page.getByText('alice-EVIDENCE-025', { exact: true }).count(), 0);
  await keyboard('Next page', 'Space');
  await page.getByText('Showing 26–50 of 130', { exact: false }).waitFor();
  assert.equal(await bodyRows().first().getByText('alice-Inventory-025', { exact: true }).count(), 1);
  assert.equal(await page.getByText('alice-EVIDENCE-000', { exact: true }).count(), 0);
  await select('Observations per page', '100');
  await page.getByText('Showing 1–100 of 130', { exact: false }).waitFor();
  assert.equal(await bodyRows().count(), 100);
  assert.equal(await page.getByText('alice-NOTES-100', { exact: true }).count(), 0);
  await select('Inventory type', 'HostSystem'); await select('Reported power state', 'poweredOff');
  await page.getByText('Showing 1–22 of 22 matching observations', { exact: false }).waitFor();
  assert.equal(await bodyRows().count(), 22);
  assert.equal(await page.getByText('alice-EVIDENCE-000', { exact: true }).count(), 0);
  const search = page.getByRole('textbox', { name: 'Search name, object ID or reported IP', exact: true });
  await search.focus(); await page.keyboard.type('ref-111');
  await page.getByText('Showing 1–1 of 1 matching observations', { exact: false }).waitFor();
  assert.equal(await bodyRows().count(), 1);
  assert.equal(await page.getByText('alice-EVIDENCE-003', { exact: true }).count(), 0);
  await search.fill('no-match');
  await page.getByText('No observations match these filters.', { exact: false }).waitFor();
  assert.equal(await table.count(), 0);
  assert.equal(await page.getByText('Complete empty inventory', { exact: true }).count(), 0);
  await keyboard('Reset filters'); await table.waitFor();
  assert.equal(await bodyRows().count(), 100);
  assert.equal(requests.length, beforeFilters, 'All page, search and filter changes are local');

  await select('Inventory type', 'HostSystem');
  await keyboard('View collection run-two');
  await page.getByText('Showing 1–25 of 130', { exact: false }).waitFor();
  assert.equal(await page.getByLabel('Observations per page').inputValue(), '25');
  assert.equal(await page.getByLabel('Inventory type').inputValue(), 'all');
  await select('Observations per page', '50'); await search.fill('Inventory-1');
  await page.evaluate(() => window.fixtureSetAccount('bob'));
  await page.getByRole('button', { name: 'View collection run-two' }).waitFor();
  assert.equal(await table.count(), 0, 'Account changes remove the old snapshot');
  await keyboard('View collection run-two'); await table.waitFor();
  assert.equal(await bodyRows().count(), 25);
  assert.equal(await search.inputValue(), '');
  assert.equal(await page.getByLabel('Observations per page').inputValue(), '25');
  assert.equal(await page.getByLabel('Reported power state').inputValue(), 'all');
  assert.equal(await table.getByText('bob-Inventory-000', { exact: true }).count(), 1);
  assert.equal(await page.getByText('alice-EVIDENCE-000', { exact: true }).count(), 0);
  await keyboard('Close'); await page.getByRole('dialog').waitFor({ state: 'hidden' });
  await keyboard('Open fixture source');
  await page.getByRole('button', { name: 'View collection run-one' }).waitFor();
  assert.equal(await table.count(), 0);
  assert.ok(requests.every(request => request.method === 'GET'));
  assert.deepEqual(errors, []);
  console.log('PASS: real Mantine drawer, readonly controls, keyboard paging, 25/50/100 bounds, local search/type/power filters, hidden metadata absence, run/account resets and close/reopen; all API responses intercepted');
} finally {
  await browser?.close();
  await server.close();
}
