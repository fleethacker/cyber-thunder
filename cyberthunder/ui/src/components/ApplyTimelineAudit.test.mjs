import assert from 'node:assert/strict';
import test from 'node:test';
import { createModuleLoader } from '../lib/moduleTestSupport.mjs';
import { mount } from '../lib/rollbackTestSupport.mjs';

const record = (seq, subject, details = {}) => ({ seq, subject, details, action: 'remediation.before_state', outcome: 'ok' });
function fixture() {
  const requests = [], renders = [];
  let listener;
  const panel = mount((hooks) => {
    const { useProposalAudit } = createModuleLoader()(new URL('./ApplyTimeline.tsx', import.meta.url), {
      react: hooks,
      '../lib/format': { fmtClock: (ts) => ts },
      '../state/AppState': { useAuditListener: (fn) => { listener = fn; } },
      '../api/client': { api: { audit: (query) => new Promise((resolve, reject) => requests.push({ query, resolve, reject })) } },
    });
    return ({ id }) => { renders.push(useProposalAudit(id)); return null; };
  }, { id: 'first' });
  return { ...panel, requests, renders, current: () => renders.at(-1), send: (r) => listener(r) };
}

test('fetched and streamed audit records are filtered to the exact proposal', async () => {
  const panel = fixture(); await panel.settle();
  assert.deepEqual(panel.requests[0].query, { subject: 'first', limit: 1000 });
  panel.requests[0].resolve({ records: [record(1, 'first'), record(2, 'second'), record(3, 'second', { proposal_id: 'first' })] });
  await panel.settle();
  panel.send(record(4, 'second'));
  panel.send(record(5, null, { proposal_id: 'first' }));
  await panel.settle();
  assert.deepEqual(panel.current().map((r) => r.seq), [1, 5]);
  panel.unmount();
});

test('a slower fetch preserves streamed evidence and deduplicates audit sequence numbers', async () => {
  const panel = fixture(); await panel.settle();
  panel.send(record(4, 'first')); await panel.settle();
  panel.requests[0].resolve({ records: [record(2, 'first'), record(4, 'first')] });
  await panel.settle();
  panel.send(record(4, 'first')); await panel.settle();
  assert.deepEqual(panel.current().map((r) => r.seq), [2, 4]);
  panel.unmount();
});

test('proposal switch hides cached records even before effects, including an unavailable next audit', async () => {
  const panel = fixture(); await panel.settle();
  panel.requests[0].resolve({ records: [record(1, 'first')] }); await panel.settle();
  assert.equal(panel.current().length, 1);
  const start = panel.renders.length;
  await panel.rerender({ id: 'second' });
  assert.ok(panel.renders.slice(start).every((records) => records.length === 0));
  panel.requests[1].reject(new Error('Audit unavailable')); await panel.settle();
  panel.send(record(2, 'first')); await panel.settle();
  assert.deepEqual(panel.current(), []);
  panel.unmount();
});

test('a late response for a previous proposal cannot replace the current proposal audit', async () => {
  const panel = fixture(); await panel.settle();
  await panel.rerender({ id: 'second' });
  panel.requests[1].resolve({ records: [record(2, 'second')] }); await panel.settle();
  panel.requests[0].resolve({ records: [record(1, 'first')] }); await panel.settle();
  assert.deepEqual(panel.current().map((r) => r.subject), ['second']);
  panel.unmount();
});
