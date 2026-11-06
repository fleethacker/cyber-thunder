// Run explicitly with CT_PLAYWRIGHT_MODULE (module URL) and CT_PERMISSION_BROWSER (Chromium executable).
// Loopback-only fixture: real identity/provider, controls and dialogs; API responses are intercepted.
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';
import react from '@vitejs/plugin-react';

const { chromium } = await import(process.env.CT_PLAYWRIGHT_MODULE || 'playwright-core');
const server = await createServer({
  root: fileURLToPath(new URL('../../', import.meta.url)), configFile: false,
  cacheDir: fileURLToPath(new URL('../../../../.build/permission-controls-vite', import.meta.url)),
  server: { host: '127.0.0.1', port: 0 },
  plugins: [react(), {
    name: 'permission-controls-fixture', enforce: 'pre',
    load(id) {
      if (id.replaceAll('\\', '/').endsWith('/state/AppState.tsx')) {
        return 'export function useAppState() { return window.permissionContext; }';
      }
    },
    configureServer(vite) {
      vite.middlewares.use('/permissions-fixture.html', async (_req, res) => {
        const html = await vite.transformIndexHtml('/permissions-fixture.html', `<!doctype html><html lang="en"><head><title>Permission controls keyboard fixture</title></head><body><div id="root"></div>
          <script type="module">
            import React, {useState} from 'react';
            import {createRoot} from 'react-dom/client';
            import {MantineProvider, Button, Stack, TextInput} from '@mantine/core';
            import '@mantine/core/styles.css';
            import {IdentityProvider, useIdentity} from '/src/state/Identity.tsx';
            import {setSessionIdentity} from '/src/api/identity.ts';
            import {PermissionProvider, PermissionButton} from '/src/components/PermissionGate.tsx';
            import {KillSwitch} from '/src/components/KillSwitch.tsx';
            import {TargetForm} from '/src/components/TargetForm.tsx';
            function Controls() {
              const {can} = useIdentity();
              const [opened, open] = useState(false);
              return React.createElement(PermissionProvider, {can}, React.createElement(Stack, {p: 'md'},
                React.createElement(TextInput, {label: 'Search', placeholder: 'Filters remain usable'}),
                React.createElement(PermissionButton, {action: 'apply', onClick: () => window.applyCalls++}, 'Apply fixture'),
                React.createElement(KillSwitch),
                React.createElement(Button, {onClick: () => open(true)}, 'Open target fixture'),
                React.createElement(TargetForm, {opened, initial: window.targetFixture, onClose: () => open(false), onSaved: () => window.savedCalls++})));
            }
            function Fixture() {
              const [permissions, setPermissions] = useState(['read', 'kill.engage']);
              const [engaged, setEngaged] = useState(false);
              window.permissionSet = setPermissions; window.permissionEngaged = setEngaged;
              window.permissionRendered = permissions;
              window.permissionContext = {actor: 'verified-fixture', status: {kill: {engaged}}, statusError: null, refresh: async () => {}};
              const identity = {mode: 'oidc', authenticated: true, login_available: true, permissions,
                principal: {actor: 'verified-fixture', name: 'Fixture user', roles: ['viewer'], kind: 'oidc'}};
              setSessionIdentity(identity);
              return React.createElement(MantineProvider, {}, React.createElement(IdentityProvider, {identity, logout: async () => {}}, React.createElement(Controls)));
            }
            window.applyCalls = 0; window.savedCalls = 0;
            window.targetFixture = {id: 'fixture', name: 'Fixture target', environment: 'production-é', asset_type: 'linux', transport: 'ssh',
              address: '192.0.2.1', in_scope: false, sudo: false, tags: [], options: {}, notes: ''};
            createRoot(document.getElementById('root')).render(React.createElement(React.StrictMode, {}, React.createElement(Fixture)));
          </script></body></html>`);
        res.setHeader('Content-Type', 'text/html'); res.end(html);
      });
    },
  }],
});

const writes = [], errors = [];
let browser;
try {
  await server.listen();
  browser = await chromium.launch({ executablePath: process.env.CT_PERMISSION_BROWSER, headless: true });
  const page = await browser.newPage();
  page.setDefaultTimeout(15000);
  page.on('pageerror', (error) => errors.push(error.message));
  await page.route('**/api/v1/**', async (route) => {
    const req = route.request(), path = new URL(req.url()).pathname;
    writes.push({ path, method: req.method(), body: req.postDataJSON() });
    const refusal = path === '/api/v1/targets/fixture';
    await route.fulfill({ status: refusal ? 403 : 200, contentType: 'application/json',
      body: JSON.stringify(refusal ? { detail: 'Destination environment is not authorized' } : {}) });
  });
  await page.goto(`${server.resolvedUrls.local[0]}permissions-fixture.html`);
  const activate = async (name, key = 'Enter') => {
    await page.getByRole('button', { name, exact: true }).focus(); await page.keyboard.press(key);
  };
  const setPermissions = async (actions) => {
    await page.evaluate((value) => window.permissionSet(value), actions);
    await page.waitForFunction((value) => JSON.stringify(window.permissionRendered) === JSON.stringify(value), actions);
  };
  const deniedApply = page.getByRole('button', { name: 'Apply fixture', exact: true });
  await deniedApply.waitFor(); assert.equal(await deniedApply.isDisabled(), true);
  const explanation = page.getByRole('group', { name: 'Apply fixture', exact: true });
  await page.getByRole('textbox', { name: 'Search', exact: true }).focus();
  await page.keyboard.press('Tab');
  assert.equal(await explanation.evaluate((element) => document.activeElement === element), true);
  await page.getByRole('tooltip').filter({ hasText: 'apply permission required' }).waitFor();
  const reasonId = await deniedApply.getAttribute('aria-describedby');
  assert.match(await page.locator(`[id="${reasonId}"]`).innerText(), /apply permission required/);
  await page.keyboard.press('Enter'); await page.keyboard.press('Space');
  assert.equal(await page.evaluate(() => window.applyCalls), 0);

  await activate('Engage kill switch');
  await page.getByRole('textbox', { name: 'Reason', exact: true }).fill('Fixture safety stop');
  await setPermissions(['read']);
  const deniedConfirm = page.getByRole('dialog').getByRole('button', { name: 'Engage kill switch', exact: true });
  await deniedConfirm.waitFor(); assert.equal(await deniedConfirm.isDisabled(), true);
  await page.getByRole('dialog').getByRole('group', { name: 'Engage kill switch', exact: true }).focus();
  await page.keyboard.press('Enter'); assert.equal(writes.length, 0);
  await activate('Cancel');
  await page.getByRole('dialog').waitFor({ state: 'hidden' });
  await setPermissions(['read', 'kill.engage']);
  await activate('Engage kill switch', 'Space');
  const engagedResponse = page.waitForResponse((response) => response.url().endsWith('/kill/engage'));
  await page.getByRole('dialog').getByRole('button', { name: 'Engage kill switch', exact: true }).click();
  await engagedResponse;
  assert.equal(writes.length, 1);
  await page.getByRole('dialog').waitFor({ state: 'hidden' });
  await page.evaluate(() => window.permissionEngaged(true));
  const release = page.getByRole('button', { name: 'Release kill switch', exact: true });
  await release.waitFor(); assert.equal(await release.isDisabled(), true);
  await setPermissions(['read', 'kill.release']);
  await activate('Release kill switch');
  assert.equal(await page.getByRole('dialog').getByRole('button', { name: 'Release', exact: true }).isDisabled(), true);
  await page.getByRole('textbox', { name: 'Reason', exact: true }).fill('Owner approved resume');
  const releasedResponse = page.waitForResponse((response) => response.url().endsWith('/kill/release'));
  await activate('Release'); await releasedResponse;
  assert.equal(writes.length, 2);
  await page.getByRole('dialog').waitFor({ state: 'hidden' });
  await page.evaluate(() => window.permissionEngaged(false));
  await setPermissions(['read', 'admin']);

  await activate('Open target fixture');
  const environment = page.getByRole('textbox', { name: 'Environment', exact: true });
  await environment.waitFor(); assert.equal(await environment.inputValue(), 'production-é');
  await environment.fill('invalid environment');
  assert.equal(await page.getByRole('button', { name: 'Save', exact: true }).isDisabled(), true);
  await environment.press('Enter'); assert.equal(writes.length, 2);
  await environment.fill('destination');
  const refusedResponse = page.waitForResponse((response) => response.url().endsWith('/targets/fixture'));
  await activate('Save'); await refusedResponse;
  await page.getByText('Destination environment is not authorized', { exact: true }).waitFor();
  assert.equal(await page.evaluate(() => window.savedCalls), 0);
  assert.equal(writes[2].body.environment, 'destination');
  await setPermissions(['read']);
  assert.equal(await page.getByRole('button', { name: 'Save', exact: true }).isDisabled(), true);
  await environment.press('Enter'); assert.equal(writes.length, 3);
  await activate('Cancel');
  await page.getByRole('dialog').waitFor({ state: 'hidden' });
  await activate('Open target fixture');
  await page.waitForFunction(() => document.querySelector('input[value="production-é"]') !== null);
  assert.equal(await environment.inputValue(), 'production-é', 'Reopening restores the saved declaration');
  assert.deepEqual(errors, []);
  console.log('Permission keyboard/browser acceptance passed: accessible denial, dynamic identity permissions, independent kill actions, environment refusal and restore; 3 intercepted requests, no live targets.');
} finally {
  await browser?.close(); await server.close();
}
