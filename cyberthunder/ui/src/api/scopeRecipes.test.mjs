import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluate } from '../lib/setupTestSupport.mjs';

test('recipe API uses shared request/auth/error handling and only the three dedicated endpoints', async (t) => {
  const calls = [], originalFetch = globalThis.fetch, originalStorage = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
  globalThis.fetch = async (url, options) => {
    calls.push({ url, ...options });
    return new Response(JSON.stringify(options.method === 'PUT' ? { detail: 'Saved recipes changed' } : {}),
      { status: options.method === 'PUT' ? 409 : 200, headers: { 'Content-Type': 'application/json' } });
  };
  Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: { getItem: () => 'IT1 Operator' } });
  t.after(() => { globalThis.fetch = originalFetch; if (originalStorage) Object.defineProperty(globalThis, 'localStorage', originalStorage); else delete globalThis.localStorage; });
  const shared = evaluate(new URL('./client.ts', import.meta.url));
  const { scopeRecipesApi } = evaluate(new URL('./scopeRecipes.ts', import.meta.url), { './client': shared });
  const input = { revision: 'revision-1', recipes: [{ id: 'range-a', name: 'Réseau', include: ['fd00::1-fd00::8'], exclude: ['fd00::4'],
    allow_public: false, scanner_target: null, acknowledge_normalization: false }] };
  await scopeRecipesApi.load(); await scopeRecipesApi.preview(input);
  const save = { ...input, preview_fingerprint: 'f'.repeat(64), reason: 'Explicit review' };
  await assert.rejects(scopeRecipesApi.save(save), (error) => error.status === 409 && error.detail === 'Saved recipes changed');
  assert.deepEqual(calls.map(({ method, url }) => [method, url]), [
    ['GET', '/api/v1/discovery/scopes/recipes'], ['POST', '/api/v1/discovery/scopes/recipes/preview'], ['PUT', '/api/v1/discovery/scopes/recipes'],
  ]);
  assert.ok(calls.every((call) => call.headers['X-Actor'] === 'IT1 Operator'));
  assert.deepEqual(JSON.parse(calls[1].body), input);
  assert.deepEqual(JSON.parse(calls[2].body), save);
});
