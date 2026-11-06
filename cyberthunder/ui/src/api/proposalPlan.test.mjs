import assert from 'node:assert/strict';
import test from 'node:test';
import { createModuleLoader } from '../lib/moduleTestSupport.mjs';

const load = createModuleLoader();
const { api, ApiError } = load(new URL('./client.ts', import.meta.url));
const { setSessionIdentity } = load(new URL('./identity.ts', import.meta.url));
setSessionIdentity({ mode: 'dev', authenticated: false, login_available: false, permissions: [] });

test('preview posts once to the encoded plan route with the named actor and preserves the response and errors', async () => {
  const previousFetch = globalThis.fetch;
  const previousStorage = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
  Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: { getItem: () => 'IT1 Reviewer' } });
  const requests = [];
  const plan = { version: 1, mode: 'static', proposal_id: 'proposal/one ?#', approved_fix_sha256: null };
  globalThis.fetch = async (url, options) => {
    requests.push({ url, options });
    return new Response(JSON.stringify(requests.length === 1 ? plan : { detail: 'No library fix is available' }), {
      status: requests.length === 1 ? 200 : 404, headers: { 'content-type': 'application/json' },
    });
  };
  try {
    assert.deepEqual(await api.plan(plan.proposal_id), plan);
    assert.equal(requests.length, 1);
    assert.equal(requests[0].url, '/api/v1/proposals/proposal%2Fone%20%3F%23/plan');
    assert.equal(requests[0].options.method, 'POST');
    assert.equal(requests[0].options.headers['X-Actor'], 'IT1 Reviewer');
    assert.equal(requests[0].options.headers['Content-Type'], 'application/json');
    assert.deepEqual(JSON.parse(requests[0].options.body), {});
    await assert.rejects(api.plan('missing'), (error) => error instanceof ApiError && error.status === 404 && error.detail === 'No library fix is available');
    assert.equal(requests.length, 2);
  } finally {
    globalThis.fetch = previousFetch;
    if (previousStorage) Object.defineProperty(globalThis, 'localStorage', previousStorage);
    else delete globalThis.localStorage;
  }
});
