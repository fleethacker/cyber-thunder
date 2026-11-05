import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluate } from '../lib/setupTestSupport.mjs';

test('host/scope clients use the agreed routes and actor header without follow-on requests', async (t) => {
  const calls = [], originalFetch = globalThis.fetch, originalStorage = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
  globalThis.fetch = async (url, options) => { calls.push({ url, ...options }); return new Response('{}', { headers: { 'Content-Type': 'application/json' } }); };
  Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: { getItem: () => 'IT1 Operator' } });
  t.after(() => { globalThis.fetch = originalFetch; if (originalStorage) Object.defineProperty(globalThis, 'localStorage', originalStorage); else delete globalThis.localStorage; });
  const { api } = evaluate(new URL('./client.ts', import.meta.url));
  const host = { id: 'host-alias', name: 'Host alias', asset_type: 'windows', transport: 'winrm', address: 'host.example', port: 5986,
    username: 'operator', credential_ref: 'HOST_REF', in_scope: false, reason: 'Registration only' };
  const ranges = { include: ['fd00::1/125'], exclude: ['fd00::4'], allow_public: false, scanner_target: 'scanner-alias', acknowledge_normalization: true };
  await api.runtimeContext(); await api.registerHost(host); await api.targetReadiness('host/alias?');
  await api.previewScopeRanges(ranges); await api.saveScopeRanges({ ...ranges, reason: 'Owner permits search' });
  assert.deepEqual(calls.map(({ method, url }) => [method, url]), [
    ['GET', '/api/v1/runtime/context'], ['POST', '/api/v1/targets/register-host'], ['GET', '/api/v1/targets/host%2Falias%3F/readiness'],
    ['POST', '/api/v1/discovery/scopes/preview'], ['PUT', '/api/v1/discovery/scopes/ranges'],
  ]);
  assert.ok(calls.every((call) => call.headers['X-Actor'] === 'IT1 Operator'));
  assert.deepEqual(JSON.parse(calls[1].body), host);
  assert.deepEqual(JSON.parse(calls[3].body), ranges);
  assert.deepEqual(JSON.parse(calls[4].body), { ...ranges, reason: 'Owner permits search' });
  assert.ok(calls.every((call) => !/\/scans|\/sweep|\/discover$/.test(call.url)));
});
