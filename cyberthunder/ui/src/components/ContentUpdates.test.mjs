import assert from 'node:assert/strict';
import test from 'node:test';
import { browser, errorText, evaluate, format, libraryFixture, linkPresentation, mount, tableStubs, text, ui } from '../lib/contentTestSupport.mjs';

async function setup(t, overrides = {}) {
  const env = browser(t), calls = [];
  let readFailure = false;
  const context = { status: { kill: { engaged: false }, link: { connected: true } }, actor: 'IT1 Operator' };
  const job = { id: 'job', state: 'queued', files: [], deltas: [], created_at: '2026-11-05T12:00:00Z', created_by: 'IT1 Operator' };
  const props = { library: libraryFixture(), dirty: false, disabled: false, view: 'updates',
    onRefresh: async () => { calls.push(['refresh']); }, onTransfers: () => { calls.push(['transfers']); }, ...overrides };
  const panel = mount((hooks) => evaluate(new URL('./ContentUpdates.tsx', import.meta.url), {
    react: hooks, '@mantine/core': ui, '@mantine/notifications': { notifications: { show() {} } },
    '../api/client': { errorText, api: {
      pullUpdates: async (body) => { calls.push(['pull', body]); return job; },
      pullJob: async (id) => { calls.push(['job', id]); if (readFailure) throw new Error('Transfer status unavailable'); return { ...job, state: 'done' }; },
      uploadContent: async (file) => { calls.push(['upload', file.name]); return { record: props.library.held.files[0] }; },
      importDir: async (path) => { calls.push(['import', path]); return { imported: [], refused: [], skipped: [], missing: [], deltas: [], verified_by: 'hash' }; },
      writeManifest: async () => { calls.push(['manifest']); return { items: [] }; },
    } }, '../lib/format': format, '../state/AppState': { useAppState: () => context }, './ActorChip': { actorProblem: () => null },
    './LibraryTables': tableStubs, './common': ui, '../lib/linkPresentation': linkPresentation,
  }).ContentUpdates, props);
  env.cleanup(() => panel.unmount()); await panel.settle();
  return { ...panel, props, calls, context, env, failRead: () => { readFailure = true; } };
}

test('viewing updates and transfers does not download; selection survives task switches', async (t) => {
  const panel = await setup(t);
  await panel.change('Download tracked.zip', true);
  await panel.rerender({ ...panel.props, view: 'transfers' });
  assert.ok(panel.nodes().some((node) => node.type === 'FileInput'));
  await panel.rerender(panel.props);
  assert.equal(panel.control('Download tracked.zip').props.checked, true);
  assert.deepEqual(panel.calls, []);
});
test('only explicit download submits selected filenames and exposes transfer progress', async (t) => {
  const panel = await setup(t);
  await panel.change('Download tracked.zip', true);
  await panel.click('Download selected (1)');
  assert.deepEqual(panel.calls[0], ['pull', { filenames: ['tracked.zip'], pace: false }]);
  assert.ok(panel.calls.some(([kind]) => kind === 'transfers'));
  assert.equal(panel.button('Download selected (1)').props.disabled, true);
  panel.env.tick(); await panel.settle();
  assert.ok(panel.calls.some(([kind]) => kind === 'job'));
});

test('leaving test mode disables pacing even when the earlier test toggle remains selected', async (t) => {
  const panel = await setup(t);
  Object.assign(panel.context.status.link, { mode: 'test', test_connected: true, kbps: 56 });
  await panel.rerender(panel.props);
  await panel.change('Pace downloads to the configured TEST rate', true);
  await panel.change('Download tracked.zip', true);
  panel.context.status.link.mode = 'production';
  await panel.rerender(panel.props);
  const pace = panel.control('Pace downloads to the configured TEST rate');
  assert.equal(pace.props.disabled, true);
  assert.equal(pace.props.checked, false);
  await panel.click('Download selected (1)');
  assert.deepEqual(panel.calls[0], ['pull', { filenames: ['tracked.zip'], pace: false }]);
});
test('dirty, disabled and offline gates refuse direct download handlers', async (t) => {
  const panel = await setup(t);
  await panel.change('Download tracked.zip', true);
  for (const changed of [{ dirty: true }, { disabled: true }, {}]) {
    if (!Object.keys(changed).length) panel.context.status.link.connected = false;
    await panel.rerender({ ...panel.props, ...changed });
    const button = panel.button('Download selected (1)');
    assert.equal(button.props.disabled, true);
    button.props.onClick(); await panel.settle();
  }
  assert.deepEqual(panel.calls, []);
});
test('transfer polling errors remain visible and do not imply completion', async (t) => {
  const panel = await setup(t);
  await panel.change('Download tracked.zip', true);
  await panel.click('Download selected (1)');
  panel.failRead(); panel.env.tick(); await panel.settle();
  assert.ok(panel.nodes().some((node) => node.props?.error === 'Transfer status unavailable'));
  assert.equal(panel.button('Download selected (1)').props.disabled, true);
});

test('restricted and unknown link status preserve selection but block download handlers and stale test pacing', async (t) => {
  const panel = await setup(t);
  panel.props.library.connected = true;
  Object.assign(panel.context.status.link, { mode: 'test', test_connected: true });
  await panel.rerender();
  await panel.change('Pace downloads to the configured TEST rate', true);
  await panel.change('Download tracked.zip', true);
  for (const change of [
    { global_details: false, link: null },
    { global_details: true, link: null },
    { global_details: false, link: { connected: true, mode: 'test', test_connected: true } },
  ]) {
    Object.assign(panel.context.status, change);
    await panel.rerender();
    assert.equal(panel.control('Download tracked.zip').props.checked, true);
    const button = panel.button('Download selected (1)');
    assert.equal(button.props.disabled, true);
    button.props.onClick(); await panel.settle();
    const pace = panel.control('Pace downloads to the configured TEST rate');
    assert.equal(pace.props.disabled, true);
    assert.equal(pace.props.checked, false);
    const message = panel.nodes().find((node) => node.type === 'Text' && text(node).includes('Download availability cannot be determined'));
    assert.ok(message);
    assert.equal(message.props.c, 'dimmed');
    assert.ok(!panel.nodes().some((node) => node.type === 'Text' && text(node).includes('while disconnected')));
  }
  assert.deepEqual(panel.calls, []);
});
test('offline upload and folder import remain explicit local operations', async (t) => {
  const panel = await setup(t, { view: 'transfers' });
  panel.context.status.link.connected = false; await panel.rerender();
  await panel.change('Choose content files', [new File(['fixture'], 'reference.xml')]);
  assert.deepEqual(panel.calls, []);
  await panel.click('Upload 1 file');
  assert.ok(panel.calls.some(([kind, name]) => kind === 'upload' && name === 'reference.xml'));
  await panel.change('Import folder on the server', '  C:/offline/content  ');
  await panel.click('Import folder');
  assert.ok(panel.calls.some(([kind, path]) => kind === 'import' && path === 'C:/offline/content'));
  assert.ok(panel.calls.every(([kind]) => ['upload', 'import', 'refresh'].includes(kind)));
});
test('manifest export is blocked by draft selections, while local imports retain their separate guard', async (t) => {
  const panel = await setup(t, { view: 'transfers', dirty: true });
  assert.equal(panel.button('Download manifest').props.disabled, true);
  panel.button('Download manifest').props.onClick(); await panel.settle();
  await panel.change('Import folder on the server', 'C:/offline/content');
  await panel.rerender({ ...panel.props, disabled: true });
  assert.equal(panel.button('Import folder').props.disabled, true);
  panel.button('Import folder').props.onClick(); await panel.settle();
  assert.deepEqual(panel.calls, []);
});
