import assert from 'node:assert/strict';
import test from 'node:test';
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
    principal: { verified: true, source: 'oidc', kind: 'human' } };
  assert.equal(canOverrideContent(valid), true);
  for (const changed of [null, { ...valid, mode: 'dev' }, { ...valid, authenticated: false },
    { ...valid, permissions: ['admin'] }, { ...valid, permissions: ['import'] },
    { ...valid, principal: { ...valid.principal, kind: 'workload' } },
    { ...valid, principal: { ...valid.principal, verified: false } },
    { ...valid, principal: { ...valid.principal, source: 'mesh' } }]) assert.equal(canOverrideContent(changed), false);
});

test('older development manifest downloads exclude server paths and API-only fields', () => {
  const { manifestText } = helpers();
  const doc = JSON.parse(manifestText({ items: [], generated_at: 'fixture-time', node: 'fixture-node',
    path: 'private-path', sha256: 'server-file-hash', authenticity: { status: 'unsigned_dev' } }));
  assert.deepEqual(doc, { items: [], generated_at: 'fixture-time', node: 'fixture-node' });
});
