import assert from 'node:assert/strict';
import test from 'node:test';
import { createModuleLoader } from './moduleTestSupport.mjs';

const load = createModuleLoader();
const { isSuppressed, isRemediationHeld, reviewDisposition, reviewDraft, reviewInput } = load(new URL('./findingAssurance.ts', import.meta.url));
const { api, ApiError } = load(new URL('../api/client.ts', import.meta.url));
const { setSessionIdentity } = load(new URL('../api/identity.ts', import.meta.url));
setSessionIdentity({ mode: 'dev', authenticated: false, login_available: false, permissions: [] });
const summary = Object.freeze({ disposition: 'unreviewed', active: false, suppressed: false, revision: 3,
  evidence_fingerprint: 'a'.repeat(64), current: null, history_count: 3, reopened_reason: null, identity_verified: false });
const now = Date.parse('2026-11-05T12:00:00Z');
const draft = Object.freeze({ disposition: 'false_positive', reason: '  Checked the baseline  ', supportingEvidence: '  Reference 4  ', expiresAt: '2026-11-06T12:00:00Z' });

test('missing and inactive reviews remain Unreviewed and never suppress proposals', () => {
  assert.equal(reviewDisposition(undefined), 'unreviewed');
  assert.equal(isSuppressed(undefined), false);
  assert.equal(isSuppressed({ ...summary, suppressed: true }), false);
  assert.equal(reviewDisposition({ ...summary, disposition: 'false_positive' }), 'unreviewed');
  assert.equal(isSuppressed({ ...summary, active: true, suppressed: true }), true);
});

test('review request has only contract fields and preserves the operator draft', () => {
  assert.deepEqual(reviewInput(draft, summary, now), {
    disposition: 'false_positive', reason: 'Checked the baseline', supporting_evidence: 'Reference 4',
    expires_at: '2026-11-06T12:00:00.000Z', expected_revision: 3, evidence_fingerprint: 'a'.repeat(64),
  });
  assert.equal(draft.reason, '  Checked the baseline  ');
  assert.equal(summary.revision, 3);
});

test('dismissals require a future expiry; malformed and past times are rejected', () => {
  for (const disposition of ['false_positive', 'not_applicable']) {
    assert.throws(() => reviewInput({ ...draft, disposition, expiresAt: '' }, summary, now), /future expiry/);
  }
  for (const expiresAt of ['bad-date', '2026-11-05T12:00:00Z', '2026-11-04T12:00:00Z']) {
    assert.throws(() => reviewInput({ ...draft, expiresAt }, summary, now), /valid future/);
  }
});

test('every decision including reversal needs a reason and current revision/evidence', () => {
  for (const disposition of ['unreviewed', 'confirmed', 'false_positive', 'not_applicable', 'needs_investigation']) {
    assert.throws(() => reviewInput({ ...draft, disposition, reason: '  ' }, summary, now), /reason/);
  }
  assert.throws(() => reviewInput(draft, { ...summary, evidence_fingerprint: '' }, now), /Refresh/);
  assert.throws(() => reviewInput(draft, { ...summary, revision: undefined }, now), /Refresh/);
  const reversal = reviewInput({ ...draft, disposition: 'unreviewed', expiresAt: '' }, summary, now);
  assert.equal(reversal.expires_at, null);
  assert.equal(reversal.disposition, 'unreviewed');
});

test('expired or reopened decisions do not prefill a dismissal for new evidence', () => {
  const current = { disposition: 'false_positive', reason: 'Old evidence', supporting_evidence: 'Old reference', expires_at: '2026-11-06T12:00:00Z' };
  assert.deepEqual(reviewDraft({ ...summary, disposition: 'false_positive', current }), {
    disposition: 'unreviewed', reason: '', supportingEvidence: '', expiresAt: '',
  });
  const active = reviewDraft({ ...summary, active: true, disposition: 'false_positive', current });
  assert.equal(active.reason, 'Old evidence');
  assert.equal(new Date(active.expiresAt).toISOString(), current.expires_at.replace('Z', '.000Z'));
});

test('risk acceptance is a distinct hold with bounded expiry and required supporting evidence', () => {
  const held = { ...summary, active: true, disposition: 'risk_accepted', remediation_held: true, risk_acceptance_status: 'active' };
  assert.equal(isSuppressed(held), false);
  assert.equal(isRemediationHeld(held), true);
  assert.equal(isRemediationHeld({ ...held, active: false }), false);
  const risk = { ...draft, disposition: 'risk_accepted' };
  assert.throws(() => reviewInput({ ...risk, supportingEvidence: ' ' }, summary, now), /Supporting evidence/);
  assert.throws(() => reviewInput({ ...risk, expiresAt: '' }, summary, now), /expiry/);
  assert.throws(() => reviewInput({ ...risk, expiresAt: new Date(now + 31 * 86400000).toISOString() }, summary, now), /30 days/);
  assert.equal(reviewInput({ ...risk, expiresAt: new Date(now + 30 * 86400000).toISOString() }, summary, now).disposition, 'risk_accepted');
  assert.equal(reviewInput({ ...risk, disposition: 'risk_revoked', expiresAt: '2020-01-01' }, summary, now).expires_at, null);
});

test('risk endpoints preserve explicit authority boundaries and never send a disposition or principal', async () => {
  const oldFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push({ url, ...options });
    return new Response('{}', { headers: { 'content-type': 'application/json' } });
  };
  try {
    const basis = { reason: 'Reviewed', expected_revision: 2, evidence_fingerprint: 'a'.repeat(64) };
    await api.acceptFindingRisk('finding/one', { ...basis, supporting_evidence: 'Evidence', expires_at: '2026-11-07T12:00:00Z' });
    await api.revokeFindingRisk('finding/one', basis);
    assert.deepEqual(calls.map(c => [c.method, c.url]), [
      ['PUT', '/api/v1/findings/finding%2Fone/risk-acceptance'],
      ['POST', '/api/v1/findings/finding%2Fone/risk-acceptance/revoke'],
    ]);
    assert.deepEqual(JSON.parse(calls[1].body), basis);
    assert.ok(calls.every(c => !('disposition' in JSON.parse(c.body)) && !('reviewed_principal' in JSON.parse(c.body))));
  } finally { globalThis.fetch = oldFetch; }
});

test('client preserves CSV query names, review route, exact PUT body and stale 409 details', async () => {
  const previousFetch = globalThis.fetch;
  const previousStorage = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
  Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: { getItem: () => 'IT1 Reviewer' } });
  const requests = [];
  globalThis.fetch = async (url, options) => {
    requests.push({ url, options });
    return options.method === 'PUT'
      ? new Response(JSON.stringify({ detail: 'Evidence changed; refresh' }), { status: 409, headers: { 'content-type': 'application/json' } })
      : new Response('{}', { headers: { 'content-type': 'application/json' } });
  };
  try {
    await api.findings({ confidence: '"high","unknown"', review: '"unreviewed","confirmed"', sort_by: 'review', sort_dir: 'desc', limit: 200, offset: 200, status: '"open"', q: 'SSH' });
    const query = new URL(requests[0].url, 'http://local.test').searchParams;
    assert.equal(query.get('confidence'), '"high","unknown"');
    assert.equal(query.get('review'), '"unreviewed","confirmed"');
    assert.equal(query.get('sort_by'), 'review');
    assert.equal(query.get('sort_dir'), 'desc');
    assert.equal(query.get('offset'), '200');
    assert.equal(query.get('status'), '"open"');
    assert.equal(query.get('q'), 'SSH');
    await api.findingReview('finding/one', 'scan-2');
    assert.equal(requests[1].url, '/api/v1/findings/finding%2Fone/review?scan_id=scan-2');
    const body = reviewInput(draft, summary, now);
    await assert.rejects(api.saveFindingReview('finding/one', body), (error) => error instanceof ApiError && error.status === 409 && error.detail === 'Evidence changed; refresh');
    assert.equal(requests[2].url, '/api/v1/findings/finding%2Fone/review');
    assert.equal(requests[2].options.method, 'PUT');
    assert.equal(requests[2].options.headers['X-Actor'], 'IT1 Reviewer');
    assert.deepEqual(JSON.parse(requests[2].options.body), body);
  } finally {
    globalThis.fetch = previousFetch;
    if (previousStorage) Object.defineProperty(globalThis, 'localStorage', previousStorage);
    else delete globalThis.localStorage;
  }
});
