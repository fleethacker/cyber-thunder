import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { evaluate } from './moduleTestSupport.mjs';

const helpers = () => evaluate(new URL('./contentAuthenticity.ts', import.meta.url), {
  '../api/identity': { sessionIdentity: () => null },
});

test('source metadata never upgrades old, unsigned or exception content into publisher assurance', () => {
  const { contentProvenance } = helpers();
  for (const evidence of [undefined, {}, { status: 'legacy_unverified' }, { status: 'unsigned_dev' },
    { status: 'human_override' }, { status: 'operator_attested', operator_attested: false }]) {
    assert.match(contentProvenance(evidence).text, /authenticity not established/i);
  }
  assert.match(contentProvenance({ status: 'trusted_https_source' }).text, /verified HTTPS; no publisher signature/);
  assert.match(contentProvenance({ status: 'operator_attested', operator_attested: true }).text, /at import; no DISA signature/);
});

test('exceptions require current verified human identity and both role permissions', () => {
  const { canOverrideContent } = helpers();
  const valid = { mode: 'oidc', authenticated: true, permissions: ['import', 'admin'],
    principal: { verified: true, source: 'oidc', kind: 'human', issuer: 'https://issuer.example.test', subject: 'reviewer' } };
  assert.equal(canOverrideContent(valid), true);
  for (const changed of [null, { ...valid, mode: 'dev' }, { ...valid, authenticated: false },
    { ...valid, permissions: ['admin'] }, { ...valid, permissions: ['import'] },
    { ...valid, principal: { ...valid.principal, kind: 'workload' } },
    { ...valid, principal: { ...valid.principal, verified: false } },
    { ...valid, principal: { ...valid.principal, source: 'mesh' } },
    { ...valid, principal: { ...valid.principal, issuer: undefined } },
    { ...valid, principal: { ...valid.principal, subject: '' } },
    { ...valid, mode: 'unrecognized', principal: { ...valid.principal, source: 'unrecognized' } }]) assert.equal(canOverrideContent(changed), false);
});

test('older development manifest downloads exclude server paths and API-only fields', () => {
  const { manifestText } = helpers();
  const doc = JSON.parse(manifestText({ items: [], generated_at: 'fixture-time', node: 'fixture-node',
    path: 'private-path', sha256: 'server-file-hash', authenticity: { status: 'unsigned_dev' } }, { mode: 'dev' }));
  assert.deepEqual(doc, { items: [], generated_at: 'fixture-time', node: 'fixture-node' });
});

test('missing artifact text never downgrades a verified or unknown session to a summary', () => {
  const { manifestText, plainUploadNeedsException } = helpers();
  for (const identity of [null, { mode: 'oidc' }, { mode: 'mesh' }]) {
    for (const authenticity of [undefined, { status: 'unsigned_dev' }, { status: 'operator_signed' }]) {
      assert.throws(() => manifestText({ items: [], authenticity }, identity), /signed download/);
    }
    assert.equal(plainUploadNeedsException(identity), true);
  }
  assert.equal(plainUploadNeedsException({ mode: 'dev' }), false);
  assert.throws(() => manifestText({ items: [], authenticity: { status: 'operator_attested' } }, { mode: 'dev' }), /signed download/);
});

test('content client preserves export bytes through JSON and sends exceptions only when provided', async (t) => {
  const { manifestText } = helpers();
  const identity = evaluate(new URL('../api/identity.ts', import.meta.url));
  identity.setSessionIdentity({ mode: 'dev', authenticated: false, permissions: [] });
  const { api } = evaluate(new URL('../api/client.ts', import.meta.url), {
    './identity': identity,
  });
  // Include escaped Unicode, quotes and a backslash to catch parse/re-serialize or double-escape changes.
  const artifact = '{"items":[],"node":"\\u00e9\\ud83d\\ude80\\\"\\\\"}';
  const digest = createHash('sha256').update(artifact).digest('hex');
  const calls = [];
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    calls.push([url, options]);
    return new Response(JSON.stringify({ download_text: artifact, items: [], sha256: digest, path: 'private' }),
      { headers: { 'content-type': 'application/json' } });
  });
  const manifest = await api.writeManifest();
  const downloaded = new Blob([manifestText(manifest)]);
  assert.equal(await downloaded.text(), artifact);
  assert.equal(createHash('sha256').update(Buffer.from(await downloaded.arrayBuffer())).digest('hex'), manifest.sha256);
  await api.importDir('C:/bundle');
  assert.deepEqual(JSON.parse(calls.at(-1)[1].body), { path: 'C:/bundle' });
  await api.importDir('C:/bundle', 'Reviewed courier');
  assert.deepEqual(JSON.parse(calls.at(-1)[1].body), { path: 'C:/bundle', override_reason: 'Reviewed courier' });
  const file = new File(['fixture'], 'content.xml');
  await api.uploadContent(file);
  assert.deepEqual([...calls.at(-1)[1].body.keys()], ['file']);
  await api.uploadContent(file, 'Reviewed courier');
  assert.equal(calls.at(-1)[1].body.get('override_reason'), 'Reviewed courier');
  assert.deepEqual([...calls.at(-1)[1].body.keys()], ['file', 'override_reason']);
});
