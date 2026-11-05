import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluate, format, libraryFixture, mount, text, ui } from '../lib/contentTestSupport.mjs';

const tables = (hooks) => evaluate(new URL('./LibraryTables.tsx', import.meta.url), { react: hooks, '@mantine/core': ui, '../lib/format': format });
test('catalog search examines all pages and keeps pagination valid after filtering', async (t) => {
  const rows = Array.from({ length: 28 }, (_, i) => ({ title: 'Product ' + i }));
  const panel = mount((hooks) => tables(hooks).LibraryTable, {
    rows, label: 'products', searchText: (p) => p.title, headings: 'Product', empty: 'Empty',
    render: (p) => ({ type: 'Text', props: { children: p.title } }),
  });
  t.after(() => panel.unmount()); await panel.settle();
  panel.control('products pages').props.onChange(3); await panel.settle();
  assert.ok(panel.nodes().some((node) => text(node) === 'Product 27'));
  await panel.change('Search products', 'Product 2');
  assert.ok(panel.nodes().some((node) => text(node) === 'Product 2'));
  assert.ok(panel.nodes().some((node) => text(node) === 'Product 27'));
  assert.ok(!panel.nodes().some((node) => node.type === 'Pagination'));
  await panel.change('Search products', 'not listed');
  assert.ok(panel.nodes().some((node) => text(node) === 'No results match your search.'));
});
test('select displayed preserves selections from other pages', async () => {
  let selected;
  const panel = mount((hooks) => tables(hooks).DisplayedSelection, { displayed: [{ id: 'shown' }], selected: ['hidden'], keyOf: (p) => p.id, onChange: (next) => { selected = next; } });
  await panel.settle(); await panel.click('Select displayed');
  assert.deepEqual(selected, ['hidden', 'shown']);
  await panel.rerender({ displayed: [{ id: 'shown' }], selected, keyOf: (p) => p.id, onChange: (next) => { selected = next; } });
  await panel.click('Clear displayed');
  assert.deepEqual(selected, ['hidden']); panel.unmount();
});
test('local file type/source and catalog origin filters keep bundled rules distinct', async (t) => {
  const file = libraryFixture().held.files[0];
  const panel = mount((hooks) => tables(hooks).HeldTable, { files: [file, { ...file, filename: 'scap.zip', kind: 'scap_benchmark', source: 'pulled' }] });
  t.after(() => panel.unmount()); await panel.settle();
  await panel.change('Local content type', 'scap_benchmark'); await panel.change('How it arrived', 'pulled');
  const table = panel.find((node) => node.type?.name === 'LibraryTable');
  assert.deepEqual(table.props.rows.map((row) => row.filename), ['scap.zip']);
  const catalogs = mount((hooks) => tables(hooks).CatalogTable, { catalogs: [{ origin: 'bundled_reference', path: 'bundled' }, { origin: 'imported_catalog', path: 'imported' }] });
  t.after(() => catalogs.unmount()); await catalogs.settle(); await catalogs.change('Catalog origin', 'bundled_reference');
  assert.deepEqual(catalogs.find((node) => node.type?.name === 'LibraryTable').props.rows.map((row) => row.path), ['bundled']);
});
