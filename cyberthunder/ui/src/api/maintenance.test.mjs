import assert from 'node:assert/strict';
import test from 'node:test';
import { createModuleLoader } from '../lib/moduleTestSupport.mjs';

test('maintenance override sends exactly one explicit bound request and never retries a fresh-login rejection', async (t) => {
  const previous = { fetch: globalThis.fetch, window: globalThis.window };
  t.after(() => Object.assign(globalThis, previous));
  globalThis.window = new EventTarget();
  const calls = [], challenges = [];
  window.addEventListener('ct:step-up', (event) => challenges.push(event.detail));
  const challenge = { reason: 'authentication_too_old', max_age: 300, acr_values: ['strong'] };
  globalThis.fetch = async (...args) => {
    calls.push(args);
    return new Response(JSON.stringify({ detail: 'Fresh authentication required', error: 'insufficient_user_authentication', step_up: challenge }),
      { status: 401, headers: { 'Content-Type': 'application/json' } });
  };
  const load = createModuleLoader();
  load(new URL('./identity.ts', import.meta.url)).setSessionIdentity({ mode: 'oidc', authenticated: true,
    csrf_token: 'fixture-csrf', permissions: ['apply', 'maintenance.override'], principal: { actor: 'human:fixture' } });
  const { api } = load(new URL('./client.ts', import.meta.url));
  const override = { binding: 'a'.repeat(64), expires_at: '2030-01-02T12:02:00Z', reason: 'Restore service for the target owner' };
  await assert.rejects(api.applyWithMaintenanceOverride('proposal/one', override), { status: 401 });
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], '/api/v1/proposals/proposal%2Fone/apply');
  assert.equal(calls[0][1].method, 'POST');
  assert.equal(calls[0][1].headers['X-CSRF-Token'], 'fixture-csrf');
  assert.deepEqual(JSON.parse(calls[0][1].body), { maintenance_override: override });
  assert.deepEqual(challenges, [challenge]);
});
