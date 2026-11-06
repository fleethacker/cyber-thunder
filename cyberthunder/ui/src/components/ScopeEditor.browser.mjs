// Run explicitly with CT_PLAYWRIGHT_MODULE (module URL) and CT_SCOPE_BROWSER (Chromium executable).
// A loopback Vite fixture renders the real editor and Mantine controls; all API requests are intercepted.
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';
import react from '@vitejs/plugin-react';

const { chromium } = await import(process.env.CT_PLAYWRIGHT_MODULE || 'playwright-core');
const root = fileURLToPath(new URL('../../', import.meta.url));
const server = await createServer({
  root, configFile: false, cacheDir: fileURLToPath(new URL('../../../../.build/scope-recipes-vite', import.meta.url)),
  server: { host: '127.0.0.1', port: 0 },
  plugins: [react(), {
    name: 'scope-editor-fixture',
    enforce: 'pre',
    resolveId(id, importer) {
      if (id === './setupAccess' && importer?.replaceAll('\\', '/').endsWith('/ScopeEditor.tsx')) return '\0scope-fixture-access';
    },
    load(id) {
      if (id === '\0scope-fixture-access' || id.replaceAll('\\', '/').endsWith('/components/setupAccess.ts')) {
        return 'export function useSetupAccess() { return null; }';
      }
    },
    configureServer(vite) {
      vite.middlewares.use('/scope-recipes-fixture.html', async (_req, res) => {
        const html = await vite.transformIndexHtml('/scope-recipes-fixture.html', `<!doctype html><html lang="en"><head><title>Scope recipe keyboard fixture</title></head><body><div id="root"></div>
          <script type="module">
            import React, {useState} from 'react';
            import {createRoot} from 'react-dom/client';
            import {MantineProvider, Button} from '@mantine/core';
            import '@mantine/core/styles.css';
            import {ScopeEditor} from '/src/components/ScopeEditor.tsx';
            localStorage.setItem('ct.actor', 'IT1 Browser');
            function Fixture() {
              const [opened, open] = useState(true);
              return React.createElement(MantineProvider, {},
                React.createElement(Button, {onClick: () => open(true)}, 'Open recipes'),
                React.createElement(ScopeEditor, {opened, current: [], onClose: () => open(false), onSaved: () => window.recipeSaved = (window.recipeSaved || 0) + 1}));
            }
            createRoot(document.getElementById('root')).render(React.createElement(React.StrictMode, {}, React.createElement(Fixture)));
          </script></body></html>`);
        res.setHeader('Content-Type', 'text/html'); res.end(html);
      });
    },
  }],
});

const input = (id, name, include, exclude, scanner_target = null, allow_public = false) => ({
  id, name, include, exclude, scanner_target, allow_public, acknowledge_normalization: false,
  networks: [...(include ?? [])], original_expressions_known: include !== null,
});
const originalA = input('range-a', 'Enclave A', ['10.20.30.1-10.20.30.9'], ['10.20.30.4']);
const originalB = input('range-b', 'Réseau B', ['fd00::1-fd00::8'], ['fd00::4'], 'scanner-b', true);
let snapshot = { revision: 'revision-1', scopes: [], recipes: [originalA, originalB] };
const requests = [], browserErrors = [];
let conflict = false;
const preview = { networks: ['10.20.30.1/32', 'fd00::1/128'], network_count: 2, input_address_count: '17',
  excluded_address_count: '2', address_count: '15', truncated: false, can_save: true, blocking_reasons: [], warnings: [],
  normalizations: [], requires_normalization_acknowledgment: false,
  limits: { max_entries: 128, max_networks: 256, max_addresses: 65536 } };
let browser;
try {
  await server.listen();
  browser = await chromium.launch({ executablePath: process.env.CT_SCOPE_BROWSER, headless: true });
  const page = await browser.newPage();
  page.setDefaultTimeout(15000);
  page.on('pageerror', (e) => browserErrors.push(e.message));
  await page.route('**/api/v1/**', async (route) => {
    const req = route.request(), path = new URL(req.url()).pathname, body = req.postDataJSON();
    requests.push({ path, method: req.method(), body });
    const respond = (json, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(json) });
    if (path === '/api/v1/targets') return respond({ targets: [{ id: 'scanner-b', name: 'Scanner B', in_scope: true }] });
    if (path === '/api/v1/discovery/scopes/recipes' && req.method() === 'GET') return respond(snapshot);
    if (path === '/api/v1/discovery/scopes/recipes/preview') return respond({ revision: body.revision,
      fingerprint: 'f'.repeat(64), preview, recipes: body.recipes.map((r) => ({ id: r.id, name: r.name, preview })) });
    if (path === '/api/v1/discovery/scopes/recipes' && req.method() === 'PUT') {
      if (conflict) return respond({ detail: 'Saved search recipes changed. Reload them and review a fresh preview before saving.' }, 409);
      snapshot = { revision: 'revision-saved', scopes: [], recipes: body.recipes.map((r) => ({ ...r,
        networks: [...(r.include ?? [])], original_expressions_known: r.include !== null })) };
      return respond({ ...snapshot, preview });
    }
    throw new Error(`Unexpected API call: ${req.method()} ${path}`);
  });
  const base = server.resolvedUrls.local[0];
  await page.goto(`${base}scope-recipes-fixture.html`);
  const field = (name) => page.getByRole('textbox', { name, exact: true });
  const activate = async (name, key = 'Enter') => {
    const button = page.getByRole('button', { name, exact: true }); await button.focus(); await page.keyboard.press(key);
  };
  const type = async (name, value) => {
    await field(name).focus(); await page.keyboard.press('ControlOrMeta+A'); await page.keyboard.insertText(value);
  };
  const selectLast = async () => {
    if (await field('Recipe to edit').inputValue() === 'Réseau B') return;
    await field('Recipe to edit').focus(); await page.keyboard.press('ArrowDown'); await page.keyboard.press('ArrowDown'); await page.keyboard.press('Enter');
  };
  const confirm = async () => {
    await activate('Preview exact search ranges');
    await field('Search range decision reason').waitFor({ state: 'visible' });
    await type('Search range decision reason', 'Keyboard review of exact scopes');
    await page.getByRole('checkbox', { name: 'I reviewed the exact effective search ranges and exclusions; inventory authorization stays unchanged' }).focus();
    await page.keyboard.press('Space');
  };
  await field('Search addresses or ranges').waitFor();
  await selectLast();
  assert.equal(await field('Recipe name').inputValue(), 'Réseau B');
  assert.equal(await field('Scanner vantage point').inputValue(), 'Scanner B (scanner-b)');
  assert.equal(await field('Exclude addresses or ranges').inputValue(), 'fd00::4');
  await type('Exclude addresses or ranges', 'fd00::5');
  await activate('Reset unsaved edits', 'Space');
  await selectLast();
  assert.equal(await field('Exclude addresses or ranges').inputValue(), 'fd00::4');
  await activate('Add recipe');
  await type('Recipe name', 'Temporary keyboard recipe');
  await type('Search addresses or ranges', '10.20.31.1');
  await activate('Remove selected recipe', 'Space');
  await selectLast();
  await type('Exclude addresses or ranges', 'fd00::5');
  await confirm();
  await activate('Confirm search ranges');
  await page.getByRole('dialog').waitFor({ state: 'hidden' });
  assert.equal(await page.evaluate(() => window.recipeSaved), 1);
  const saved = requests.find((r) => r.method === 'PUT').body;
  assert.deepEqual(saved.recipes[0], Object.fromEntries(Object.entries(originalA).filter(([k]) => !['networks', 'original_expressions_known'].includes(k))));
  assert.equal(saved.recipes[1].scanner_target, 'scanner-b');
  assert.equal(saved.recipes[1].allow_public, true);
  assert.deepEqual(saved.recipes[1].exclude, ['fd00::5']);
  await activate('Open recipes');
  await field('Search addresses or ranges').waitFor(); await selectLast();
  assert.equal(await field('Exclude addresses or ranges').inputValue(), 'fd00::5');
  await type('Exclude addresses or ranges', 'fd00::6');
  await page.keyboard.press('Escape');
  await page.getByRole('dialog').waitFor({ state: 'hidden' });
  await activate('Open recipes'); await field('Search addresses or ranges').waitFor(); await selectLast();
  assert.equal(await field('Exclude addresses or ranges').inputValue(), 'fd00::5');
  conflict = true;
  await confirm(); await activate('Confirm search ranges');
  await page.getByText('Saved search recipes changed while this editor was open.', { exact: false }).waitFor();
  assert.equal(await page.getByRole('button', { name: 'Confirm search ranges', exact: true }).isDisabled(), true);
  snapshot = { revision: 'revision-other', scopes: [], recipes: [input('legacy', 'Legacy range', null, null, 'scanner-b', true)] };
  snapshot.recipes[0].networks = ['fd00::/124'];
  await activate('Reload saved recipes');
  await page.getByText('Original include/exclude expressions are unknown', { exact: false }).waitFor();
  assert.equal(await field('Search addresses or ranges').count(), 0);
  await activate('Use effective ranges as new expressions');
  assert.equal(await field('Search addresses or ranges').inputValue(), 'fd00::/124');
  assert.equal(await field('Scanner vantage point').inputValue(), 'Scanner B (scanner-b)');
  await activate('Reset unsaved edits');
  assert.equal(await field('Search addresses or ranges').count(), 0);
  assert.equal(requests.filter((r) => r.method === 'PUT').length, 2, 'Only the explicit save and refused stale save were submitted');
  assert.deepEqual(browserErrors, []);
  console.log('PASS: keyboard selection, mixed policies, reset, add/remove, explicit save, reopen, Escape, stale revision and legacy conversion/reset');
} finally {
  await browser?.close();
  await server.close();
}
