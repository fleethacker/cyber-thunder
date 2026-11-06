import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import test from 'node:test';
import { createElement as h } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createModuleLoader } from '../lib/moduleTestSupport.mjs';

const require = createRequire(import.meta.url);
const core = require('@mantine/core');
const visible = (html) => html.replace(/<style\b[^>]*>[\s\S]*?<\/style>/g, '').replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
const reassessment = {
  version: 1, status: 'not_reassessed', reason: 'partial_collection', view: 'current',
  explanation: 'The later scan collected only partial results and did not reassess this observation.',
  observation: { observed_at: '2026-11-05T10:00:00Z', source: 'native', scan_id: 'original-scan' },
  latest_attempt: { scan_id: 'partial-scan', started_at: '2026-11-05T12:00:00Z', finished_at: null, target_status: 'partial' },
};
function loader() {
  const load = createModuleLoader();
  load(new URL('../lib/format.ts', import.meta.url), {
    dayjs: { default: require('dayjs') }, 'dayjs/plugin/relativeTime': { default: require('dayjs/plugin/relativeTime') },
  });
  return load;
}
function panel(value, compact = false) {
  const { FindingReassessment } = loader()(new URL('./FindingReassessment.tsx', import.meta.url));
  return renderToStaticMarkup(h(core.MantineProvider, {}, h(FindingReassessment, { reassessment: value, compact })));
}

test('retained evidence and later attempt have separate source-bound times and a neutral explanation', () => {
  const before = structuredClone(reassessment);
  const text = visible(panel(reassessment));
  for (const phrase of ['Not reassessed', reassessment.explanation, 'Observation:', 'native', 'original-scan',
    'Later scan: partial-scan', 'target partial', 'does not mean fixed or false positive',
    'does not change evidence confidence, human review or approvals']) assert.ok(text.includes(phrase), phrase);
  assert.equal((text.match(/UTC/g) || []).length, 2);
  assert.deepEqual(reassessment, before);
});

test('row badge is a keyboard-accessible button and never invents a badge from missing history', () => {
  assert.match(panel(reassessment, true), /<button[^>]*aria-label="Not reassessed: show later scan and original observation"/);
  for (const value of [null, undefined, { ...reassessment, status: 'unknown', latest_attempt: null },
    { ...reassessment, status: 'no_known_gap', latest_attempt: null }]) assert.equal(visible(panel(value, true)), '');
  assert.match(visible(panel(null)), /server has not reported reassessment history/);
});

test('unknown observation times remain unknown and run text is escaped', () => {
  const value = { ...reassessment, observation: { observed_at: null, source: null, scan_id: null },
    latest_attempt: { ...reassessment.latest_attempt, scan_id: '<img src=x onerror=alert(1)>' } };
  const html = panel(value);
  assert.match(visible(html), /Time not recorded · Source not recorded/);
  assert.match(html, /&lt;img/); assert.doesNotMatch(html, /<img\b|<a\b/);
});

function drawer(f) {
  const load = loader();
  let read = 0;
  const { FindingDrawer } = load(new URL('./FindingDrawer.tsx', import.meta.url), {
    '@mantine/core': { ...core, Drawer: ({ opened, children }) => opened ? h('section', {}, children) : null },
    '../lib/hooks': { useAsync: () => ({ data: read++ === 0 ? f : [], loading: false, error: null, setData() {}, reload: async () => {} }) },
  });
  const { PermissionProvider } = load(new URL('./PermissionGate.tsx', import.meta.url));
  return renderToStaticMarkup(h(core.MantineProvider, {}, h(PermissionProvider, { can: (action) => ['explain', 'propose'].includes(action) },
    h(FindingDrawer, { findingId: f.id, onClose() {} }))));
}
test('drawer integration preserves scanner result, confidence, review, rollback and action permissions', () => {
  const f = { id: 'ssh', host: 'alpha', title: 'SSH root login', rule_id: 'ssh-root', source: 'native', references: [],
    collected_at: reassessment.observation.observed_at, severity: 'high', status: 'not_reviewed', scanner_status: 'not_a_finding',
    needs_rescan: true, evidence: 'Original scanner evidence', confidence: { grade: 'low', reason: 'Original confidence', reasons: [] },
    review: { disposition: 'false_positive', active: true, suppressed: true, current: { reason: 'Original human review' } } };
  const controls = (html) => [...html.matchAll(/<button\b[^>]*>[\s\S]*?<\/button>/g)].map(([button]) => [visible(button), /\sdisabled(?:=|\s|>)/.test(button)]);
  const before = drawer(f), after = drawer({ ...f, reassessment });
  for (const phrase of ['Original scanner evidence', 'Original confidence', 'Original human review', 'needs rescan after rollback', 'Not reassessed']) assert.ok(visible(after).includes(phrase), phrase);
  assert.deepEqual(controls(after), controls(before));
  assert.match(after, /aria-label="Low confidence: show reasons"/);
});
