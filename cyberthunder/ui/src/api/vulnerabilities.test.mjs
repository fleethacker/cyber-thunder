import assert from 'node:assert/strict';
import test from 'node:test';
import { createModuleLoader } from '../lib/moduleTestSupport.mjs';

const load = createModuleLoader();
const { api, ApiError } = load(new URL('./client.ts', import.meta.url));
const { setSessionIdentity } = load(new URL('./identity.ts', import.meta.url));
setSessionIdentity({ mode: 'dev', authenticated: false, login_available: false, permissions: [] });

function transport(t, handler) {
  const previousFetch = globalThis.fetch;
  const previousStorage = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
  Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: { getItem: () => 'IT1 Reviewer' } });
  const calls = [];
  globalThis.fetch = async (url, options) => { calls.push({ url, ...options }); return handler(url, options); };
  t.after(() => {
    globalThis.fetch = previousFetch;
    if (previousStorage) Object.defineProperty(globalThis, 'localStorage', previousStorage);
    else delete globalThis.localStorage;
  });
  return calls;
}
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

test('status and progress reads use GET only, including encoded job IDs', async (t) => {
  const response = { jobs: [], state: 'missing' };
  const calls = transport(t, () => json(response));
  assert.deepEqual(await api.vulnerabilities(), response);
  await api.vulnerabilityJobs();
  await api.vulnerabilityJob('job/one ?#');
  assert.deepEqual(calls.map((call) => call.url), ['/api/v1/vulnerabilities', '/api/v1/vulnerabilities/jobs', '/api/v1/vulnerabilities/jobs/job%2Fone%20%3F%23']);
  assert.ok(calls.every((call) => call.method === 'GET' && call.body === undefined));
});

test('explicit update and schedule save carry the actor, selection and expected revision', async (t) => {
  const calls = transport(t, () => json({ revision: 5 }));
  await api.updateVulnerabilityDatabases(false);
  const input = { expected_revision: 4, auto_update: true, interval_hours: 12, include_java: true };
  assert.deepEqual(await api.saveVulnerabilitySettings(input), { revision: 5 });
  assert.deepEqual(calls.map((call) => [call.method, call.url, JSON.parse(call.body)]), [
    ['POST', '/api/v1/vulnerabilities/update', { include_java: false }],
    ['PUT', '/api/v1/vulnerabilities/settings', input],
  ]);
  assert.ok(calls.every((call) => call.headers['X-Actor'] === 'IT1 Reviewer'));
});

test('offline import sends the exact ZIP bytes, and export requests an actor-attributed binary POST', async (t) => {
  const file = new File([new Uint8Array([0x50, 0x4b, 3, 4, 0, 255])], 'databases.zip');
  const calls = transport(t, (url) => url.endsWith('/import') ? json({ state: 'stale', provenance: 'offline_import' }) : new Response(file, { headers: { 'content-type': 'application/zip' } }));
  assert.equal((await api.importVulnerabilityBundle(file)).provenance, 'offline_import');
  const exported = await api.exportVulnerabilityBundle();
  assert.deepEqual(await exported.arrayBuffer(), await file.arrayBuffer());
  assert.equal(calls[0].body, file);
  assert.equal(calls[0].headers['Content-Type'], 'application/zip');
  assert.equal(calls[1].headers.Accept, 'application/zip');
  assert.equal(calls[1].body, undefined);
  assert.ok(calls.every((call) => call.method === 'POST' && call.headers['X-Actor'] === 'IT1 Reviewer'));
});

test('JSON conflicts and binary-operation errors remain visible with their status and detail', async (t) => {
  let status = 409;
  const calls = transport(t, () => json({ detail: 'Fixture operation refused' }, status));
  const operations = [() => api.saveVulnerabilitySettings({ expected_revision: 1 }), () => api.importVulnerabilityBundle(new File(['zip'], 'db.zip')), () => api.exportVulnerabilityBundle()];
  for (const code of [409, 413, 423]) {
    status = code;
    for (const operation of operations) await assert.rejects(operation, (error) => error instanceof ApiError && error.status === code && error.detail === 'Fixture operation refused');
  }
  assert.equal(calls.length, 9);
});

test('ZIP network failures use the standard visible API error', async (t) => {
  transport(t, () => { throw new Error('fixture connection lost'); });
  await assert.rejects(api.exportVulnerabilityBundle(), (error) => error instanceof ApiError && error.status === 0 && error.detail.includes('fixture connection lost'));
});
