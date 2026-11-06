import assert from 'node:assert/strict';
import test from 'node:test';
import { browser, errorText, evaluate, format, mount, text, ui } from '../lib/contentTestSupport.mjs';

const rowHelpers = evaluate(new URL('../lib/findingRow.ts', import.meta.url));
test('rollback rescan flags never become verified-fix labels, and other result changes stay neutral', () => {
  const rollback = { needs_rescan: true, scanner_status: 'not_a_finding', status: 'not_reviewed', rollback: { proposal_id: 'old', finished_at: '2026-11-05T12:00:00Z', ok: true } };
  assert.equal(rowHelpers.findingResultLabel(rollback), 'Current result · needs rescan after rollback');
  assert.equal(rowHelpers.findingResultLabel({ scanner_status: 'open', status: 'not_reviewed' }), 'Current result');
  assert.equal(rowHelpers.findingResultLabel({ remediated: { proposal_id: 'fix' } }), 'Current result after verified fix');
  assert.equal(rowHelpers.findingResultLabel({ ...rollback, remediated: { proposal_id: 'old-fix' } }), 'Current result · needs rescan after rollback');
});
const pointer = (options = {}) => ({
  button: 0, defaultPrevented: false, target: { closest: () => null },
  currentTarget: { contains: () => true }, ...options,
});
test('whole-row click opens details while nested controls and portal content stay independent', () => {
  let opened = 0;
  const handlers = rowHelpers.findingRowHandlers(() => opened++);
  handlers.onClick(pointer());
  assert.equal(opened, 1);
  for (const selector of ['button', 'input', 'label', 'a', '[role="checkbox"]', '[data-row-action]']) {
    handlers.onClick(pointer({ target: { closest: (query) => query.includes(selector) ? {} : null } }));
  }
  handlers.onClick(pointer({ currentTarget: { contains: () => false } }));
  handlers.onClick(pointer({ defaultPrevented: true }));
  handlers.onClick(pointer({ button: 2 }));
  assert.equal(opened, 1);
});
test('Enter and Space on the row open once and prevent scrolling; nested keys are untouched', () => {
  let opened = 0, prevented = 0;
  const handlers = rowHelpers.findingRowHandlers(() => opened++);
  const row = {};
  for (const key of ['Enter', ' ']) handlers.onKeyDown({ target: row, currentTarget: row, key, preventDefault: () => prevented++ });
  handlers.onKeyDown({ target: row, currentTarget: row, key: ' ', repeat: true, preventDefault: () => prevented++ });
  handlers.onKeyDown({ target: {}, currentTarget: row, key: ' ', preventDefault: () => prevented++ });
  handlers.onKeyDown({ target: row, currentTarget: row, key: 'ArrowDown', preventDefault: () => prevented++ });
  assert.equal(opened, 2); assert.equal(prevented, 3);
});
test('Findings retains semantic table rows, a detail button, and the separate review entry point', async (t) => {
  browser(t);
  const finding = { id: 'finding-one', title: 'Check SSH', rule_id: 'rule-one', rule_version: 'STIG-1', host: 'server', status: 'not_reviewed',
    scanner_status: 'not_a_finding', needs_rescan: true,
    severity: 'high', categories: ['stig'], source: 'scanner', references: [], review: null,
    collected_at: '2026-11-05T10:30:00Z', reassessment: { status: 'not_reassessed',
      observation: { observed_at: '2026-11-05T10:00:00Z' }, latest_attempt: { started_at: '2026-11-05T12:00:00Z' } } };
  let result;
  const panel = mount((hooks) => {
    const libHooks = evaluate(new URL('../lib/hooks.ts', import.meta.url), { react: hooks, '../api/client': { errorText } });
    return evaluate(new URL('./Findings.tsx', import.meta.url), {
      react: hooks, '@mantine/core': ui, '@mantine/hooks': { useDebouncedValue: (value) => [value] },
      '@mantine/notifications': { notifications: { show() {} } }, '../api/client': { errorText, api: { findings: async () => result } },
      '../components/common': ui, '../components/FindingDrawer': ui, '../components/FindingAssurance': ui,
      '../components/FindingReassessment': ui,
      '../lib/findingAssurance': { CONFIDENCE_LABELS: {}, REVIEW_LABELS: {} }, '../lib/format': format,
      '../lib/hooks': libHooks, '../lib/findingRow': rowHelpers,
    }).default;
  });
  result = { findings: [finding], total: 1, unfiltered_total: 1, offset: 0, facets: { confidence: [], review: [] } };
  t.after(() => panel.unmount()); await panel.settle();
  const body = () => panel.find((node) => node.type === 'AsyncView').props.children(result);
  const row = () => panel.nodes(body()).find((node) => node.type === 'Table.Tr' && node.props.tabIndex === 0);
  assert.equal(row().props.role, undefined, 'Native row semantics are preserved');
  assert.equal(row().props['aria-haspopup'], 'dialog');
  assert.match(row().props.className, /finding-row/);
  assert.match(text(row()), /needs rescan after rollback/);
  assert.doesNotMatch(text(row()), /verified fix/);
  assert.match(text(row()), /2026-11-05T10:00:00Z/);
  const badge = panel.nodes(body()).find((node) => node.type === 'FindingReassessment');
  assert.equal(badge.props.reassessment, finding.reassessment);
  assert.equal(badge.props.compact, true);
  const observed = () => text(panel.nodes(row()).filter((node) => node.type === 'Table.Td')[8]);
  assert.equal(observed(), '2026-11-05T10:00:00Z');
  finding.reassessment.observation.observed_at = null;
  assert.equal(observed(), 'Not recorded', 'An unknown API observation time must not fall back to collection or scan start time');
  delete finding.reassessment;
  assert.equal(observed(), finding.collected_at, 'Legacy servers retain their recorded collection timestamp');
  assert.ok(panel.nodes(body()).some((node) => node.type === 'Button' && node.props.children === 'View details'));
  panel.nodes(body()).find((node) => node.type === 'ReviewBadge').props.onClick();
  row().props.onClick(pointer({ target: { closest: () => ({}) } })); await panel.settle();
  assert.equal(panel.find((node) => node.type === 'FindingDrawer').props.initialReviewOpen, true);
  row().props.onClick(pointer()); await panel.settle();
  assert.equal(panel.find((node) => node.type === 'FindingDrawer').props.initialReviewOpen, false);
  assert.equal(panel.find((node) => node.type === 'FindingDrawer').props.findingId, 'finding-one');
});
