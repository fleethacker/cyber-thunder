import assert from 'node:assert/strict';
import test from 'node:test';
import { ApiError, errorText, evaluate, format, libraryFixture, mount, tableStubs, tasks, text, ui } from '../lib/contentTestSupport.mjs';

async function setup(t, options = {}) {
  let library = options.library ?? libraryFixture(), fail = false;
  const calls = [], dirty = [];
  const props = { library, disabled: false, view: 'browse', onDirtyChange: (value) => { dirty.push(value); },
    onSaved: async () => { calls.push(['refresh']); props.library = library; panel.setProps(props); }, ...options.props };
  const panel = mount((hooks) => evaluate(new URL('./LibrarySelections.tsx', import.meta.url), {
    react: hooks, '@mantine/core': ui, '@mantine/notifications': { notifications: { show() {} } },
    '../api/client': { ApiError, errorText, api: { async saveLibraryPreferences(body) {
      calls.push(['save', structuredClone(body)]);
      if (fail) throw new ApiError(409, 'Selections changed elsewhere');
      library = { ...library, preferences: { ...body, revision: body.revision + 1 } };
      return library.preferences;
    } } }, '../lib/format': format, '../lib/contentTasks': tasks, './LibraryTables': tableStubs, './common': ui,
  }).LibrarySelections, props);
  t.after(() => panel.unmount()); await panel.settle();
  return { ...panel, props, calls, dirty, table: () => panel.find((node) => node.type === 'LibraryTable'),
    fail: () => { fail = true; }, update: (next) => { library = next; } };
}

test('browse shows the full returned catalog and separates maintenance from local content', async (t) => {
  const panel = await setup(t);
  assert.equal(panel.table().props.rows.length, 3);
  assert.equal(panel.control('Maintain Tracked Server').props.checked, true);
  assert.equal(panel.control('Maintain Local Reference').props.checked, false);
  assert.ok(panel.nodes().some((node) => node.type === 'Text' && text(node).includes('V2R1')));
  assert.ok(panel.nodes().some((node) => node.type === 'Text' && text(node).includes('V1R1')));
  assert.ok(panel.nodes().some((node) => node.type === 'Text' && text(node).includes('not a guarantee of every cyber.mil')));
  assert.deepEqual(panel.calls, []);
});

test('draft selections survive task changes and save only by explicit action', async (t) => {
  const panel = await setup(t);
  await panel.change('Maintain Local Reference', true);
  assert.equal(panel.dirty.at(-1), true);
  assert.deepEqual(panel.calls, []);
  assert.ok(panel.nodes().some((node) => text(node) === 'Draft: add'));
  await panel.rerender({ ...panel.props, view: 'maintained' });
  assert.deepEqual(panel.table().props.rows.map((p) => p.product_key), ['tracked', 'local']);
  assert.equal(panel.control('Maintain Local Reference').props.checked, true);
  await panel.rerender({ ...panel.props, view: 'browse' });
  await panel.click('Save selections');
  assert.deepEqual(panel.calls[0][1].products, ['local', 'tracked']);
  assert.equal(panel.calls[0][1].revision, 2);
  assert.equal(panel.calls[0][1].auto_pull, false);
  assert.equal(panel.dirty.at(-1), false);
  assert.deepEqual(panel.calls.map(([name]) => name), ['save', 'refresh']);
});

test('maintained includes pending removals until saved or discarded', async (t) => {
  const panel = await setup(t, { props: { view: 'maintained' } });
  await panel.change('Maintain Tracked Server', false);
  assert.equal(panel.table().props.rows.length, 1);
  assert.ok(panel.nodes().some((node) => text(node) === 'Draft: remove'));
  await panel.click('Discard changes');
  assert.equal(panel.control('Maintain Tracked Server').props.checked, true);
  assert.equal(panel.dirty.at(-1), false);
});

test('filters and search cover versions and products outside inventory', async (t) => {
  const panel = await setup(t);
  await panel.change('Content type', 'scap_benchmark');
  assert.deepEqual(panel.table().props.rows.map((p) => p.product_key), ['scap']);
  assert.match(panel.table().props.searchText(panel.table().props.rows[0]), /scap_benchmark|scap benchmark/i);
  await panel.click('Clear product filters');
  await panel.change('Saved maintenance', 'other');
  assert.deepEqual(panel.table().props.rows.map((p) => p.product_key), ['local', 'scap']);
  await panel.change('Catalog comparison', 'update_available');
  assert.deepEqual(panel.table().props.rows.map((p) => p.product_key), ['local']);
  assert.match(tasks.productSearch(panel.table().props.rows[0]), /V1R1/);
});

test('inventory mode needs an explicit switch before product checkboxes can be edited', async (t) => {
  const library = libraryFixture(); library.preferences.mode = 'inventory';
  const panel = await setup(t, { library });
  assert.equal(panel.control('Maintain Local Reference').props.disabled, true);
  await panel.click('Choose products manually');
  assert.equal(panel.control('Maintain Local Reference').props.disabled, false);
  assert.equal(panel.control('Maintain Tracked Server').props.checked, true);
  assert.deepEqual(panel.calls, []);
});

test('refresh or 409 conflict retains the draft and requires loading saved settings', async (t) => {
  const panel = await setup(t);
  await panel.change('Maintain Local Reference', true);
  panel.fail();
  await panel.click('Save selections');
  assert.equal(panel.control('Maintain Local Reference').props.checked, true);
  assert.equal(panel.button('Save selections').props.disabled, true);
  assert.ok(panel.nodes().some((node) => node.props?.error === 'Selections changed elsewhere'));
  const next = { ...panel.props.library, preferences: { ...panel.props.library.preferences, revision: 3, products: ['scap'] } };
  panel.update(next); await panel.rerender({ ...panel.props, library: next });
  assert.equal(panel.control('Maintain Local Reference').props.checked, true);
  await panel.click('Load saved selections');
  assert.equal(panel.control('Maintain Local Reference').props.checked, false);
  assert.equal(panel.control('Maintain Automation Benchmark').props.checked, true);
  assert.equal(panel.dirty.at(-1), false);
});

test('disabled changes cannot save or alter selection through handlers', async (t) => {
  const panel = await setup(t);
  await panel.change('Maintain Local Reference', true);
  await panel.rerender({ ...panel.props, disabled: true });
  panel.button('Save selections').props.onClick();
  panel.control('Maintain Tracked Server').props.onChange({ currentTarget: { checked: false } });
  await panel.settle();
  assert.equal(panel.control('Maintain Tracked Server').props.checked, true);
  assert.deepEqual(panel.calls, []);
});

test('product detail links show saved maintenance and do not imply scanner readiness', async (t) => {
  const panel = await setup(t, { props: { productKey: 'local' } });
  assert.equal(panel.find((node) => node.type === 'Drawer').props.opened, true);
  assert.ok(panel.nodes().some((node) => node.type === 'Alert' && node.props.title === 'Content is not scanner coverage'));
  assert.deepEqual(panel.calls, []);
  await panel.rerender({ ...panel.props, productKey: 'not-in-catalog' });
  assert.equal(panel.find((node) => node.type === 'Drawer').props.opened, true);
  assert.ok(panel.nodes().some((node) => node.type === 'Alert' && text(node).includes('not in this node')));
});
