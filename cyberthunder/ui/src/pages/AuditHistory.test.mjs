import assert from 'node:assert/strict';
import test from 'node:test';
import { browser, errorText, evaluate, mount, ui } from '../lib/rollbackTestSupport.mjs';

test('older audit records remain loadable when filters match nothing in the current window', async (t) => {
  const env = browser(t), calls = [];
  const record = (seq, action) => ({ seq, action, actor: 'IT1 Operator', subject: 'old-proposal', details: {}, ts: '2026-10-29T12:00:00Z', outcome: 'ok' });
  const api = {
    auditVerify: async () => ({ count: 1000 }),
    audit: async (query) => { calls.push(query); return { records: query.after_seq === 500 ? [record(999, 'scan.finished')] : [record(100, 'proposal.verified')] }; },
  };
  const panel = mount((hooks) => evaluate(new URL('./Audit.tsx', import.meta.url), {
    react: { ...hooks, Fragment: 'Fragment' }, '@mantine/core': ui, '../api/client': { api, errorText },
    '../components/common': ui, '../components/AuditSubject': ui, '../lib/format': { fmtTime: (value) => value },
    '../state/AppState': { useAppState: () => ({ stream: 'open', refresh() {} }), useAuditListener() {} },
  }).default);
  env.cleanup(() => panel.unmount());
  await panel.settle();
  await panel.change('Action (prefix)', 'proposal.');
  assert.ok(panel.button('Load older records'));
  await panel.click('Load older records');
  assert.equal(calls.length, 2);
  assert.equal(calls[1].after_seq, 0);
  assert.ok(panel.nodes().some((node) => node.type === 'AuditSubject' && node.props.record.subject === 'old-proposal'));
});
