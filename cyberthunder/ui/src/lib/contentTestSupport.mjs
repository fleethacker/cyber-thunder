import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import ts from 'typescript';

const require = createRequire(import.meta.url);
const compound = (name) => Object.assign(() => null, Object.fromEntries(
  ['Tr', 'Td', 'Th', 'Thead', 'Tbody', 'ScrollContainer', 'Group', 'List', 'Tab', 'Panel', 'Item', 'Control'].map((part) => [part, name + '.' + part])));
const widgets = new Map();
export const ui = new Proxy({}, { get: (_, name) => {
  if (['Table', 'Tabs', 'Accordion', 'Radio', 'Checkbox'].includes(name)) {
    if (!widgets.has(name)) widgets.set(name, compound(name));
    return widgets.get(name);
  }
  return name;
} });
export function evaluate(url, imports = {}) {
  const { outputText } = ts.transpileModule(readFileSync(url, 'utf8'), {
    fileName: url.pathname, compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020, jsx: ts.JsxEmit.ReactJSX },
  });
  const exports = {};
  new Function('require', 'exports', outputText)((name) => imports[name] ?? require(name), exports);
  return exports;
}
export const { ApiError, errorText } = evaluate(new URL('../api/client.ts', import.meta.url));
export const tasks = evaluate(new URL('./contentTasks.ts', import.meta.url));
export const format = { fmtZonedTime: (at, missing = 'Not recorded') => at || missing, fmtTime: (at) => at, fmtSeconds: (n) => n + ' seconds', fmtBytes: (n) => n + ' bytes', statusColor: () => 'blue' };
export const labels = { manual_stig: 'Manual STIG', srg: 'SRG', scap_benchmark: 'SCAP benchmark' };
export const tableStubs = { ...ui, LibraryTable: 'LibraryTable', HeldTable: 'HeldTable', AvailableTable: 'AvailableTable', CatalogTable: 'CatalogTable', FileProvenance: 'FileProvenance', DisplayedSelection: 'DisplayedSelection', KIND_LABELS: labels, kindLabel: (kind) => labels[kind] ?? kind };
const same = (a, b) => !!a && !!b && a.length === b.length && a.every((v, i) => Object.is(v, b[i]));

export function mount(factory, initialProps = {}) {
  const cells = [];
  let index = 0, dirty = true, tree, effects = [], props = initialProps;
  const hooks = {
    useState(initial) {
      const cell = cells[index++] ??= { value: typeof initial === 'function' ? initial() : initial };
      cell.set ??= (update) => {
        const value = typeof update === 'function' ? update(cell.value) : update;
        if (!Object.is(value, cell.value)) { cell.value = value; dirty = true; }
      };
      return [cell.value, cell.set];
    },
    useRef(value) { return cells[index++] ??= { current: value }; },
    useMemo(fn, deps) {
      const slot = index++;
      if (!same(cells[slot]?.deps, deps)) cells[slot] = { value: fn(), deps };
      return cells[slot].value;
    },
    useCallback(fn, deps) { return hooks.useMemo(() => fn, deps); },
    useEffect(fn, deps) {
      const slot = index++, previous = cells[slot];
      if (!same(previous?.deps, deps)) {
        const cell = cells[slot] = { deps };
        effects.push(() => { previous?.cleanup?.(); cell.cleanup = fn(); });
      }
    },
  };
  const component = factory(hooks);
  async function settle() {
    for (let pass = 0; pass < 30; pass++) {
      if (dirty) {
        dirty = false; index = 0; effects = [];
        tree = component(props);
        effects.forEach((effect) => effect());
      }
      await new Promise((resolve) => setImmediate(resolve));
      if (!dirty) return;
    }
    throw new Error('Component did not settle');
  }
  function nodes(value) {
    if (Array.isArray(value)) return value.flatMap(nodes);
    if (!value || typeof value !== 'object') return [];
    const rendered = value.type === 'LibraryTable' ? value.props.rows.map(value.props.render) : null;
    return [value, ...nodes(value.props?.children), ...nodes(value.props?.right), ...nodes(value.props?.action), ...nodes(rendered)];
  }
  const find = (predicate) => { const node = nodes(tree).find(predicate); assert.ok(node, 'Expected UI element'); return node; };
  const control = (name) => find((node) => node.props?.label === name || node.props?.['aria-label'] === name);
  const button = (name) => find((node) => node.type === 'Button' && text(node.props.children) === name);
  return {
    settle, control, find, button, nodes: (value = tree) => nodes(value),
    setProps(next) { props = next; dirty = true; },
    async rerender(next = props) { props = next; dirty = true; await settle(); },
    async change(name, value) {
      const node = control(name); assert.ok(!node.props.disabled);
      node.props.onChange(['Select', 'MultiSelect', 'Radio.Group', 'Checkbox.Group', 'FileInput'].includes(node.type) ? value : { currentTarget: { value, checked: value } });
      await settle();
    },
    async click(name) { const node = button(name); assert.ok(!node.props.disabled); node.props.onClick(); await settle(); },
    unmount() { cells.forEach((cell) => cell.cleanup?.()); },
  };
}
export function text(value) {
  if (Array.isArray(value)) return value.map(text).join('');
  if (typeof value === 'string' || typeof value === 'number') return String(value);
  return value?.props ? text(value.props.children) : '';
}
export function browser(t) {
  const cleanups = [];
  const original = { window: globalThis.window, document: globalThis.document, storage: Object.getOwnPropertyDescriptor(globalThis, 'localStorage') };
  const timers = new Map(), values = new Map(); let next = 0;
  globalThis.window = {
    setInterval(fn) { const id = ++next; timers.set(id, fn); return id; }, clearInterval(id) { timers.delete(id); },
    setTimeout(fn) { const id = ++next; timers.set(id, () => { timers.delete(id); fn(); }); return id; }, clearTimeout(id) { timers.delete(id); },
  };
  globalThis.document = { createElement: () => ({ click() {}, remove() {} }), body: { appendChild() {} } };
  Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: { getItem: (key) => values.get(key) ?? null, setItem: (key, value) => values.set(key, value) } });
  t.after(() => {
    cleanups.forEach((cleanup) => cleanup());
    globalThis.window = original.window; globalThis.document = original.document;
    if (original.storage) Object.defineProperty(globalThis, 'localStorage', original.storage); else delete globalThis.localStorage;
  });
  return { cleanup: (fn) => cleanups.push(fn), tick: () => [...timers.values()].forEach((fn) => fn()) };
}

export function libraryFixture() {
  const available = (product_key, kind = 'manual_stig') => ({ product_key, kind, filename: product_key + '.zip', version: [2, 1], version_label: 'V2R1', upload_date: '2026-10-28', allowed: true, sunset: false, expected_bytes: 40, held_version: null });
  const held = { ...available('local'), version_label: 'V1R1', source: 'uploaded', fetched_at: '2026-10-29T12:00:00Z', fetched_by: 'IT1 Operator', bytes: 40, ingest: {} };
  return {
    catalog: { source: 'snapshot', saved_at: null, total_entries: 300 },
    sync: { last_attempt_at: null, last_attempt_status: null, last_error: null, last_successful_check_at: null, last_download_at: null, last_import_at: held.fetched_at },
    preferences: { mode: 'selected', products: ['tracked'], kinds: ['manual_stig'], check_on_reconnect: false, auto_pull: false, revision: 2, updated_at: null, updated_by: null },
    products: [
      { product_key: 'tracked', title: 'Tracked Server', kinds: ['manual_stig'], selected: true, recommended: true, targets: ['server'], status: 'not_downloaded', available: [available('tracked')], held: [] },
      { product_key: 'local', title: 'Local Reference', kinds: ['manual_stig'], selected: false, recommended: false, targets: [], status: 'update_available', available: [available('local')], held: [held] },
      { product_key: 'scap', title: 'Automation Benchmark', kinds: ['scap_benchmark'], selected: false, recommended: false, targets: [], status: 'not_downloaded', available: [available('scap', 'scap_benchmark')], held: [] },
    ],
    selection: { wanted: [available('tracked')], updates: [available('tracked')], current: [], skipped: [] },
    held: { files: [held], products: [], scap: [], quarantine: [] }, catalogs: [], jobs: [], connected: true, check_interval_s: 0,
  };
}
