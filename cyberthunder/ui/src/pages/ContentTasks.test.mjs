import assert from 'node:assert/strict';
import test from 'node:test';
import { browser, errorText, evaluate, format, libraryFixture, mount, tasks, text, ui } from '../lib/contentTestSupport.mjs';

async function setup(t, query = '', initial = {}) {
  const env = browser(t), calls = [];
  let params = new URLSearchParams(query);
  const context = { actor: 'IT1 Operator', status: { kill: { engaged: false }, link: { connected: true } }, statusError: null, ...initial };
  const library = libraryFixture();
  const panel = mount((hooks) => {
    const libHooks = evaluate(new URL('../lib/hooks.ts', import.meta.url), { react: hooks, '../api/client': { errorText } });
    return evaluate(new URL('./Content.tsx', import.meta.url), {
      react: hooks, '@mantine/core': ui, 'react-router-dom': { useSearchParams: () => [params, (next) => { params = next; void panel.rerender(); }] },
      '../api/client': { errorText, api: { stigLibrary: async () => { calls.push('read'); return library; }, checkUpdates: async () => { calls.push('check'); } } },
      '../components/ActorChip': { actorProblem: (actor) => actor ? null : 'Set a name' },
      '../components/ContentUpdates': { ContentUpdates: 'ContentUpdates', jobRunning: (job) => ['running', 'queued'].includes(job.state) },
      '../components/LibrarySelections': ui, '../components/LibraryTables': ui, '../components/common': ui,
      '../lib/format': format, '../lib/hooks': libHooks, '../state/AppState': { useAppState: () => context }, '../lib/contentTasks': tasks,
    }).default;
  });
  env.cleanup(() => panel.unmount()); await panel.settle();
  return { ...panel, calls, context, env, library, params: () => params,
    tabs: () => panel.find((node) => node.type === ui.Tabs),
    selections: () => panel.find((node) => node.type === 'LibrarySelections'),
  };
}
test('old library links resolve to task views and product links encode special characters', () => {
  assert.equal(tasks.contentTask('library'), 'downloaded');
  assert.equal(tasks.contentTask('selections'), 'maintained');
  assert.equal(tasks.contentTask('transfers'), 'transfers');
  assert.equal(tasks.contentTask(null, 'product'), 'browse');
  assert.equal(tasks.libraryProductHref('A&B / product'), '/content?tab=browse&product=A%26B%20%2F%20product');
});
test('mount, task navigation and background refresh only read local library state', async (t) => {
  const panel = await setup(t, 'tab=selections&keep=value');
  assert.equal(panel.tabs().props.value, 'maintained');
  assert.equal(panel.tabs().props.keepMounted, true);
  for (const task of ['browse', 'updates', 'transfers', 'downloaded']) {
    panel.tabs().props.onChange(task); await panel.settle();
    assert.equal(panel.tabs().props.value, task);
    assert.equal(panel.params().get('keep'), 'value');
    assert.equal(panel.nodes().filter((node) => node.type === 'LibrarySelections').length, 1);
  }
  panel.env.tick(); await panel.settle();
  assert.ok(panel.calls.length >= 2);
  assert.ok(panel.calls.every((call) => call === 'read'));
});
test('product detail deep links and closing the drawer preserve unrelated parameters', async (t) => {
  const panel = await setup(t, 'tab=library&keep=value');
  panel.find((node) => node.type === 'HeldTable').props.onProductSelect('local');
  await panel.settle();
  assert.equal(panel.tabs().props.value, 'browse');
  assert.equal(panel.selections().props.productKey, 'local');
  panel.selections().props.onProductChange(null); await panel.settle();
  assert.equal(panel.params().has('product'), false);
  assert.equal(panel.params().get('keep'), 'value');
});
test('dirty selections block a check across task changes; clean checks are explicit', async (t) => {
  const panel = await setup(t);
  panel.selections().props.onDirtyChange(true); await panel.settle();
  panel.tabs().props.onChange('updates'); await panel.settle();
  const button = panel.button('Check cyber.mil for updates');
  assert.equal(button.props.disabled, true);
  button.props.onClick(); await panel.settle();
  assert.ok(!panel.calls.includes('check'));
  panel.selections().props.onDirtyChange(false); await panel.settle();
  await panel.click('Check cyber.mil for updates');
  assert.equal(panel.calls.filter((call) => call === 'check').length, 1);
});
test('offline, actor, kill and unavailable status prevent live checks', async (t) => {
  const panel = await setup(t);
  for (const change of [
    { actor: '', status: { kill: { engaged: false }, link: { connected: true } }, statusError: null },
    { actor: 'IT1 Operator', status: { kill: { engaged: true }, link: { connected: true } } },
    { status: { kill: { engaged: false }, link: { connected: false } } },
    { status: { kill: { engaged: false }, link: { connected: true } }, statusError: 'Unavailable' },
  ]) {
    Object.assign(panel.context, change); await panel.rerender();
    assert.equal(panel.button('Check cyber.mil for updates').props.disabled, true);
    panel.button('Check cyber.mil for updates').props.onClick(); await panel.settle();
  }
  assert.ok(!panel.calls.includes('check'));
});
test('local freshness, import times and scanner limitations stay explicit', async (t) => {
  const panel = await setup(t);
  assert.ok(panel.nodes().some((node) => text(node).includes('Last successful cyber.mil check')));
  assert.ok(panel.nodes().some((node) => text(node) === 'No successful check recorded'));
  assert.ok(panel.nodes().some((node) => text(node) === panel.library.sync.last_import_at));
  assert.ok(panel.nodes().some((node) => node.type === 'Alert' && text(node).includes('do not confirm scan coverage')));
});
