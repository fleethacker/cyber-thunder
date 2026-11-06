import assert from 'node:assert/strict';
import test from 'node:test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import * as Mantine from '@mantine/core';
import { createModuleLoader } from '../lib/moduleTestSupport.mjs';
import { browser, format, libraryFixture, linkPresentation, mount, tableStubs, text, ui } from '../lib/contentTestSupport.mjs';

const hash = letter => letter.repeat(64);
const human = subject => ({ mode: 'oidc', authenticated: true, permissions: ['import', 'admin'], csrf_token: 'fixture-session',
  principal: { issuer: 'https://fixture.invalid', subject, actor: subject, source: 'oidc', kind: 'human', verified: true, roles: ['admin'] } });
const review = (generation = hash('a')) => ({ code: 'content_publication_review', mode: 'downgrade',
  expected_generation: generation, candidate_sha256: hash('b'), candidate_bytes: 10, review_sha256: hash('c'),
  candidate: [{ id: 'Fixture_STIG', kind: 'manual_stig', scheme: 'disa', release: [2, 11] }],
  current: [{ id: 'Fixture_STIG', release: [2, 12], sha256: hash('d'), floor: [2, 12] }] });

async function setup(t, target = 'folder') {
  const env = browser(t), load = createModuleLoader(), calls = [];
  const identity = load(new URL('../api/identity.ts', import.meta.url));
  identity.setSessionIdentity(human('alice'));
  const { ApiError } = load(new URL('../api/client.ts', import.meta.url));
  const props = { library: libraryFixture(), view: 'transfers', dirty: false, disabled: false, onRefresh: async () => {} };
  props.library.held.generation = hash('a');
  let nextError = null, waiting = null;
  const send = async (...args) => {
    calls.push(args);
    if (!args[3]) throw new ApiError(409, JSON.stringify(review()));
    if (waiting) await waiting;
    if (nextError) throw nextError;
    return args[0] === 'upload' ? { record: { filename: 'fixture.xml', version_label: 'V2R11',
      commit_status: 'committed_with_bookkeeping_pending', ingest: {} }, delta: null }
      : { imported: [{ commit_status: 'committed_with_bookkeeping_pending' }], refused: [], skipped: [], missing: [], deltas: [], verified_by: 'fixture' };
  };
  const panel = mount(hooks => load(new URL('./ContentUpdates.tsx', import.meta.url), {
    react: hooks, '@mantine/core': ui, '@mantine/notifications': { notifications: { show() {} } },
    '../api/client': { api: { uploadContent: (...args) => send('upload', ...args), importDir: (...args) => send('folder', ...args) }, errorText: e => e.message },
    '../state/AppState': { useAppState: () => ({ status: { kill: { engaged: false }, link: { connected: false } } }) },
    '../lib/format': format, '../lib/linkPresentation': linkPresentation, './LibraryTables': tableStubs, './common': ui,
    './PermissionGate': { usePermissions: () => ({ can: action => identity.sessionIdentity()?.permissions.includes(action) }) },
  }).ContentUpdates, props);
  env.cleanup(() => panel.unmount()); await panel.settle();
  const file = new File(['fixture'], 'fixture.xml');
  if (target === 'file') {
    await panel.change('Request an exception for unsigned content or an unknown signer', true);
    await panel.change('Reason for the content exception', 'Separate authenticity reason');
    await panel.change('Choose content files', [file]);
    await panel.click('Upload 1 file');
  } else {
    await panel.change('Import folder on the server', 'fixture-folder');
    await panel.click('Import folder');
  }
  return { ...panel, props, calls, identity, file, ApiError, fail: error => { nextError = error; },
    hold() { let release; waiting = new Promise(resolve => { release = resolve; }); return release; },
    async confirm() {
      await panel.change('Reason for exceptional activation', 'Reviewed older release for this fixture');
      await panel.change('I reviewed the releases and digests and intend this activation', true);
    },
  };
}

for (const target of ['file', 'folder']) test(`${target} review needs a separate reason and confirmation, sends exact binding once`, async t => {
  const panel = await setup(t, target);
  assert.equal(panel.calls.length, 1, '409 must never resubmit');
  assert.ok(!panel.nodes().some(node => typeof node.props?.error === 'string' && node.props.error.includes('content_publication_review')));
  assert.ok(!panel.nodes().some(node => typeof node.props?.children === 'string' && node.props.children.includes('content_publication_review')));
  assert.ok(panel.button('Confirm this activation').props.disabled);
  panel.button('Confirm this activation').props.onClick(); await panel.settle();
  assert.equal(panel.calls.length, 1);
  await panel.confirm();
  const retained = panel.button('Confirm this activation').props.onClick;
  retained(); retained(); await panel.settle();
  assert.equal(panel.calls.length, 2);
  const sent = panel.calls[1][3];
  for (const key of ['mode', 'expected_generation', 'candidate_sha256', 'review_sha256']) assert.equal(sent[key], review()[key]);
  assert.equal(sent.reason, 'Reviewed older release for this fixture');
  assert.notEqual(sent.reason, panel.calls[1][2]);
  assert.match(sent.request_id, /^[a-f0-9-]{36}$/);
  assert.ok(panel.nodes().some(node => text(node).includes('bookkeeping is pending')));
});

for (const change of ['file', 'folder', 'account', 'session', 'generation', 'unmount']) test(`retained confirmation is invalid after ${change} changes`, async t => {
  const panel = await setup(t, change === 'file' ? 'file' : 'folder');
  await panel.confirm();
  const retained = panel.button('Confirm this activation').props.onClick;
  if (change === 'file') await panel.change('Choose content files', [new File(['other'], 'other.xml')]);
  if (change === 'folder') await panel.change('Import folder on the server', 'other-folder');
  if (change === 'account') panel.identity.setSessionIdentity(human('bob'));
  if (change === 'session') panel.identity.setSessionIdentity({ ...human('alice'), csrf_token: 'different-session' });
  if (change === 'generation') await panel.rerender({ ...panel.props, library: { ...panel.props.library,
    held: { ...panel.props.library.held, generation: hash('e') } } });
  if (change === 'unmount') panel.unmount();
  retained(); await panel.settle();
  assert.equal(panel.calls.length, 1);
});

for (const status of [401, 409]) test(`${status} after confirmation cannot reuse consent or retry automatically`, async t => {
  const panel = await setup(t);
  await panel.confirm();
  panel.fail(new panel.ApiError(status, status === 409 ? JSON.stringify(review(hash('e'))) : 'Reauthenticate'));
  const retained = panel.button('Confirm this activation').props.onClick;
  retained(); await panel.settle();
  assert.equal(panel.calls.length, 2);
  retained(); await panel.settle();
  assert.equal(panel.calls.length, 2);
  if (status === 409) {
    assert.equal(panel.control('Reason for exceptional activation').props.value, '');
    assert.equal(panel.control('I reviewed the releases and digests and intend this activation').props.checked, false);
  } else assert.ok(!panel.nodes().some(node => node.props?.label === 'Reason for exceptional activation'));
});

test('review parser rejects malformed or unbounded data', () => {
  const load = createModuleLoader();
  const { publicationReview } = load(new URL('./ContentUpdates.tsx', import.meta.url), { '../lib/format': format, './LibraryTables': tableStubs, './common': ui, '../state/AppState': {} });
  for (const value of [{}, { ...review(), candidate: Array(17).fill(review().candidate[0]) },
    { ...review(), current: [{ ...review().current[0], sha256: 'invalid' }] },
    { ...review(), candidate: [{ id: '<script>', release: [-1, 1] }] }]) {
    assert.equal(publicationReview({ status: 409, detail: JSON.stringify(value) }), null);
  }
  assert.equal(publicationReview({ status: 409, detail: JSON.stringify(review()) }).candidate_sha256, hash('b'));
});


for (const changed of ['file', 'folder', 'generation', 'session']) test(`a late review response cannot restore consent after ${changed} changes`, async t => {
  const panel = await setup(t, changed === 'file' ? 'file' : 'folder');
  await panel.confirm();
  const retainedChange = panel.control(changed === 'file' ? 'Choose content files' : 'Import folder on the server').props.onChange;
  const release = panel.hold();
  panel.fail(new panel.ApiError(409, JSON.stringify(review())));
  await panel.click('Confirm this activation');
  if (changed === 'file') retainedChange([new File(['other'], 'other.xml')]);
  if (changed === 'folder') retainedChange({ currentTarget: { value: 'other-folder' } });
  if (changed === 'generation') await panel.rerender({ ...panel.props, library: { ...panel.props.library,
    held: { ...panel.props.library.held, generation: hash('e') } } });
  if (changed === 'session') panel.identity.setSessionIdentity({ ...human('alice'), csrf_token: 'new-session' });
  await panel.settle(); release(); await panel.settle();
  assert.equal(panel.calls.length, 2);
  assert.ok(!panel.nodes().some(node => node.props?.label === 'Reason for exceptional activation'));
  if (changed === 'file') assert.equal(panel.control('Choose content files').props.value[0].name, 'other.xml');
});

test('exception review renders releases, full digests and separate accessible controls with real Mantine', async t => {
  const panel = await setup(t);
  const root = panel.find(node => node.type === 'Paper' && text(node).includes('Review exceptional content activation'));
  function actual(node) {
    if (Array.isArray(node)) return node.map(actual);
    if (!React.isValidElement(node)) return node;
    const type = node.type === ui.Checkbox ? Mantine.Checkbox : typeof node.type === 'string'
      ? node.type.split('.').reduce((value, key) => value?.[key], Mantine) ?? node.type : node.type;
    return React.createElement(type, { ...node.props, key: node.key }, actual(node.props.children));
  }
  const html = renderToStaticMarkup(React.createElement(Mantine.MantineProvider, {}, actual(root)));
  assert.match(html, /Candidate/); assert.match(html, /Current/);
  assert.ok(html.includes(hash('b')) && html.includes(hash('d')));
  assert.match(html, /Reason for exceptional activation/);
  assert.match(html, /type="checkbox"/);
  assert.match(html, /Confirm this activation/);
});


test('client preserves the separate intent in JSON and multipart without automatic retry', async t => {
  browser(t);
  const load = createModuleLoader();
  const identity = load(new URL('../api/identity.ts', import.meta.url));
  identity.setSessionIdentity(human('alice'));
  const { api } = load(new URL('../api/client.ts', import.meta.url));
  const sent = [];
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    sent.push({ url, ...options });
    return new Response(JSON.stringify({ detail: review() }), { status: 409, headers: { 'content-type': 'application/json' } });
  });
  const intent = { ...review(), request_id: 'fixture-request-00001', reason: 'Review reason' };
  await assert.rejects(api.importDir('fixture-folder', 'Authenticity reason', intent), error => error.status === 409);
  await assert.rejects(api.uploadContent(new File(['fixture'], 'fixture.xml'), 'Authenticity reason', intent), error => error.status === 409);
  assert.equal(sent.length, 2);
  assert.equal(JSON.parse(sent[0].body).publication_intent.request_id, intent.request_id);
  assert.equal(JSON.parse(sent[1].body.get('publication_intent')).reason, intent.reason);
  assert.equal(sent[1].body.get('override_reason'), 'Authenticity reason');
});
