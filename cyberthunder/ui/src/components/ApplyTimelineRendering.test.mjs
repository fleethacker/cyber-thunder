import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createModuleLoader } from '../lib/moduleTestSupport.mjs';
import { proposal } from '../lib/rollbackTestSupport.mjs';

const require = createRequire(import.meta.url);
const { MantineProvider } = require('@mantine/core');
const load = createModuleLoader();
const timeline = load(new URL('./ApplyTimeline.tsx', import.meta.url), {
  '../state/AppState': { useAuditListener() {} },
  '../lib/format': { fmtClock: (ts) => ts },
});
const render = (p, records) => renderToStaticMarkup(createElement(MantineProvider, {},
  createElement(records ? timeline.ApplyTimelineView : timeline.ApplyTimeline, { proposal: p, records })));
const failed = (note, extra = {}) => ({ ...proposal('failed'), ...extra,
  history: [{ state: 'applying' }, ...(extra.history ?? []), { state: 'failed', note }],
});

test('capture failure with an allocated snapshot never renders capture or recovery success', () => {
  const html = render(failed('error during apply: capture failed'));
  assert.doesNotMatch(html, /Before-state captured|Rolling back|Scope check passed/);
  assert.match(html, /Before-state capture unconfirmed/);
  assert.match(html, /Rollback outcome unknown/);
});

test('maintenance and authorization stops before payload do not imply recovery', () => {
  for (const reason of ['maintenance window closed', 'authorization revoked']) {
    const html = render(failed(`stopped before apply: ${reason}`));
    assert.doesNotMatch(html, /Before-state captured|Rolling back|Verification failed/);
    assert.match(html, /Stopped before apply/);
    assert.match(html, new RegExp(reason));
  }
});

test('post-apply capture failure is not diagnosed as a verification failure from its generic note', () => {
  const html = render(failed('error during verify: post-apply capture failed', { history: [{ state: 'applied' }] }));
  assert.doesNotMatch(html, /Verification failed|Rolling back/);
  assert.match(html, /Change failed/);
  assert.match(html, /post-apply capture failed/);
});

test('issued runbook is operator work awaiting verification', () => {
  const p = { ...proposal('applied'), history: [{ state: 'applied',
    note: 'runbook issued to operator; verify after the steps are done; changed=False' }] };
  const html = render(p);
  assert.match(html, /Runbook issued/);
  assert.match(html, /Awaiting operator steps and verification/);
  assert.doesNotMatch(html, />Applied<|>Verifying</);
});

test('saved verified status remains positive with unavailable audit and incomplete history', () => {
  const html = render({ ...proposal('verified'), history: [] });
  assert.match(html, /Verified/);
  assert.doesNotMatch(html, /Before-state captured|Rolling back/);
});

test('saved rollback remains positive without assigning the approval actor or a recovery mode', () => {
  const html = render({ ...proposal('rolled_back'), history: [] });
  assert.match(html, /Rolled back/);
  assert.doesNotMatch(html, /by operator|IT1 Approver|Automatic rollback|Verifying/);
});

const event = (action, details = {}, outcome = 'ok', seq = 1, actor = 'IT2 Restore') =>
  ({ action, details, outcome, seq, actor, subject: 'old-change', ts: '2026-11-06T12:00:00Z' });
const row = (html, key) => html.match(new RegExp(`<div[^>]*data-step="${key}"[^>]*>`))?.[0];

test('successful capture evidence renders a positive milestone beside pending application', () => {
  const html = render(failed('stopped before apply: scope changed'), [event('remediation.before_state')]);
  assert.match(html, /Before-state captured/);
  assert.match(row(html, 'before'), /data-state="done"/);
  assert.match(row(html, 'applied'), /data-state="pending"/);
  assert.doesNotMatch(row(html, 'applied'), /data-active/);
});

test('manual verification and runbook issuance stay visibly pending without a spinner or check mark', () => {
  for (const records of [[event('remediation.runbook_issued')],
    [event('remediation.verify', { rule_passed: null, health: true }, 'manual')]]) {
    const html = render(proposal('applied'), records);
    assert.match(row(html, 'verified'), /data-state="pending"/);
    assert.doesNotMatch(html, /Verifying|Verified ✓|tabler-icon-loader/);
  }
});

test('automatic and manual recovery render completion and the recorded rollback actor', () => {
  for (const [actor, reason] of [['agent', 'verify failed'], ['IT2 Restore', 'manual']]) {
    const html = render(proposal('failed'), [event('remediation.rollback', { ok: true, reason }, 'ok', 9, actor)]);
    assert.match(row(html, 'rolled_back'), /data-state="done"/);
    assert.match(html, new RegExp(`Recorded rollback actor: ${actor}`));
    assert.doesNotMatch(html, /IT1 Approver|Rolling back|by operator/);
  }
});

test('failed recovery after verification stays red and keeps the actual error escaped', () => {
  const html = render(proposal('verified'), [event('remediation.rollback_started', {}, 'ok', 1),
    event('proposal.rollback_error', { error: 'restore failed <script>unsafe</script>' }, 'error', 2)]);
  assert.match(row(html, 'rolled_back'), /data-state="failed"/);
  assert.match(row(html, 'rolled_back'), /red/);
  assert.match(html, /Rollback failed/);
  assert.match(html, /restore failed &lt;script&gt;unsafe&lt;\/script&gt;/);
  assert.doesNotMatch(html, /Rolling back|Rolled back|<script>/);
});

test('blocked recovery and unmatched start receipts never render active recovery', () => {
  for (const records of [[event('remediation.rollback_preflight', { status: 'blocked' }, 'blocked')],
    [event('remediation.rollback_started')]]) {
    const html = render(proposal('failed'), records);
    assert.doesNotMatch(row(html, 'rolled_back'), /data-active|data-state="done"/);
    assert.doesNotMatch(html, /Rolling back|Rolled back/);
  }
});

test('unrelated cached audit cannot render capture, verification or rollback success', () => {
  const records = ['remediation.before_state', 'proposal.verified', 'proposal.rolled_back'].map((action) =>
    ({ ...event(action), subject: 'another-proposal', details: { proposal_id: 'old-change' } }));
  const html = render(proposal('failed'), records);
  assert.doesNotMatch(html, /Before-state captured|Verified ✓|Rolled back|Rolling back/);
});

test('old successful verification remains historical after a saved rollback', () => {
  const html = render({ ...proposal('rolled_back'), history: [{ to: 'verified', at: '2026-11-05T12:00:00Z' }] });
  assert.match(row(html, 'verified'), /data-state="done"/);
  assert.match(row(html, 'rolled_back'), /data-state="done"/);
  assert.match(html, /Historical result before rollback/);
});

test('successful rollback receipt makes verification historical before the saved state catches up', () => {
  const html = render(proposal('verified'), [event('remediation.rollback', { ok: true })]);
  assert.match(row(html, 'rolled_back'), /data-state="done"/);
  assert.match(html, /Historical result before rollback/);
});

test('limited applied history is explicitly ambiguous between payload and runbook', () => {
  const html = render({ ...proposal('applied'), history: [] });
  assert.match(row(html, 'applied'), /data-state="pending"/);
  assert.match(html, /Payload completion is unconfirmed/);
  assert.doesNotMatch(html, /Application recorded|>Applied<|>Verifying</);
});
