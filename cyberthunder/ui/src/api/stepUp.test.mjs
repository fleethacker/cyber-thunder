import assert from 'node:assert/strict';
import test from 'node:test';
import { createModuleLoader } from '../lib/moduleTestSupport.mjs';

const challenge = { reason: 'authentication_too_old', max_age: 300, acr_values: ['urn:ct:test:strong'] };
const body = { detail: 'Fresh authentication is required.', error: 'insufficient_user_authentication', step_up: challenge };
const identity = { mode: 'oidc', authenticated: true, login_available: true, csrf_token: 'fixture-csrf',
  principal: { actor: 'human:fixture', name: 'Reviewer', roles: ['approver'] }, permissions: ['approve'] };

function setup(t, result = body, status = 401) {
  const previous = { fetch: globalThis.fetch, window: globalThis.window };
  globalThis.window = new EventTarget();
  const calls = [], challenges = [], expired = [];
  window.addEventListener('ct:step-up', event => challenges.push(event.detail));
  window.addEventListener('ct:session-expired', () => expired.push(true));
  globalThis.fetch = async (...args) => { calls.push(args); return new Response(JSON.stringify(result), { status }); };
  const load = createModuleLoader();
  const metadata = load(new URL('./identity.ts', import.meta.url));
  metadata.setSessionIdentity(identity);
  const client = load(new URL('./client.ts', import.meta.url));
  t.after(() => Object.assign(globalThis, previous));
  return { ...client, metadata, calls, challenges, expired };
}

test('401 step-up preserves the session and purpose, emits a bounded challenge, and never replays a mutation', async t => {
  const f = setup(t);
  await assert.rejects(f.api.approve('change', 'reviewed', 'receipt', 'independent review'), error => {
    assert.equal(error.status, 401);
    assert.deepEqual(error.stepUp, challenge);
    return true;
  });
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0][0], '/api/v1/proposals/change/approve');
  assert.deepEqual(JSON.parse(f.calls[0][1].body), { note: 'reviewed', assessment_id: 'receipt', assessment_note: 'independent review' });
  assert.deepEqual(f.challenges, [challenge]);
  assert.deepEqual(f.expired, []);
  assert.equal(f.metadata.sessionIdentity(), identity);
});

test('ordinary 401 expires identity rather than manufacturing a step-up challenge', async t => {
  const f = setup(t, { detail: 'Authentication failed' });
  await assert.rejects(f.api.approve('change'), { status: 401 });
  assert.equal(f.metadata.sessionIdentity(), null);
  assert.equal(f.expired.length, 1);
  assert.deepEqual(f.challenges, []);
  assert.equal(f.calls.length, 1);
});

test('malformed, oversized and unknown challenges are not accepted', () => {
  const metadata = createModuleLoader()(new URL('./identity.ts', import.meta.url));
  for (const patch of [{ reason: 'untrusted-provider-secret' }, { max_age: '300' }, { max_age: 9999 },
    { acr_values: ['bad\r\nheader'] }, { acr_values: ['same', 'same'] }, { acr_values: ['x'.repeat(129)] }]) {
    assert.equal(metadata.parseStepUpChallenge({ ...body, step_up: { ...challenge, ...patch } }), undefined);
  }
  assert.deepEqual(metadata.parseStepUpChallenge({ ...body, step_up: { ...challenge, private_claims: 'not retained' } }), challenge);
});

test('a role refusal cannot trigger reauthentication and local demo stays explicitly unverified', async t => {
  const f = setup(t, body, 403);
  await assert.rejects(f.api.approve('change'), { status: 403 });
  assert.deepEqual(f.challenges, []);
  f.metadata.setSessionIdentity({ mode: 'dev', authenticated: false, permissions: [] });
  f.metadata.stepUpRequired(challenge);
  assert.deepEqual(f.challenges, []);
});
