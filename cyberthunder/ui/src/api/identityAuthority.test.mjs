import assert from 'node:assert/strict';
import test from 'node:test';
import { createModuleLoader } from '../lib/moduleTestSupport.mjs';

const first = { mode: 'oidc', authenticated: true, login_available: true, csrf_token: 'session-one',
  principal: { issuer: 'https://issuer.test', subject: 'one', actor: 'human:one', name: 'One',
    source: 'oidc', verified: true, roles: ['viewer', 'auditor'] }, permissions: ['read', 'export'] };
const second = { ...first, csrf_token: 'session-two', principal: { ...first.principal, subject: 'two', actor: 'human:two' } };
const deferred = () => { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; };

test('authority is stable across equivalent polls and changes with account, mode, session and rights', () => {
  const m = createModuleLoader()(new URL('./identity.ts', import.meta.url));
  m.setSessionIdentity(first); const revision = m.authorityRevision();
  m.setSessionIdentity({ ...first, principal: { ...first.principal, name: 'New display name', roles: ['auditor', 'viewer'] },
    permissions: ['export', 'read'] });
  assert.equal(m.authorityRevision(), revision);
  for (const changed of [second, { ...second, mode: 'mesh' }, { ...second, csrf_token: 'session-three' },
    { ...second, permissions: ['read'] }, { ...second, principal: { ...second.principal, roles: ['viewer'] } }, null]) {
    const previous = m.authorityRevision(); m.setSessionIdentity(changed);
    assert.ok(m.authorityRevision() > previous);
  }
});

for (const status of [200, 401]) test(`late ${status} response cannot publish old data or expire the new account`, async t => {
  const old = { window: globalThis.window, fetch: globalThis.fetch };
  globalThis.window = new EventTarget();
  const expired = [], challenges = [];
  window.addEventListener('ct:session-expired', () => expired.push(true));
  window.addEventListener('ct:step-up', e => challenges.push(e.detail));
  const pending = deferred(); globalThis.fetch = () => pending.promise;
  t.after(() => Object.assign(globalThis, old));
  const load = createModuleLoader(), metadata = load(new URL('./identity.ts', import.meta.url));
  const client = load(new URL('./client.ts', import.meta.url));
  metadata.setSessionIdentity(first);
  const result = client.api.targets();
  metadata.setSessionIdentity(second);
  pending.resolve(new Response(JSON.stringify({ detail: 'old account private data', error: 'insufficient_user_authentication',
    step_up: { reason: 'authentication_too_old', max_age: 300, acr_values: ['strong'] } }),
    { status, headers: { 'Content-Type': 'application/json' } }));
  await assert.rejects(result, error => error.status === 0 && !error.message.includes('private data'));
  assert.equal(metadata.sessionIdentity(), second);
  assert.deepEqual(expired, []); assert.deepEqual(challenges, []);
});

test('account change during body decoding discards an old successful response', async t => {
  const old = globalThis.fetch, pending = deferred();
  globalThis.fetch = async () => ({ ok: true, headers: new Headers({ 'Content-Type': 'application/json' }), json: () => pending.promise });
  t.after(() => { globalThis.fetch = old; });
  const load = createModuleLoader(), metadata = load(new URL('./identity.ts', import.meta.url));
  metadata.setSessionIdentity(first);
  const result = load(new URL('./client.ts', import.meta.url)).api.targets();
  await new Promise(setImmediate);
  metadata.setSessionIdentity(second); pending.resolve({ targets: ['old private target'] });
  await assert.rejects(result, { status: 0 });
});
