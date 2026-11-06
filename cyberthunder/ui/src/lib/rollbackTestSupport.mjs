import assert from 'node:assert/strict';
import { evaluate } from './moduleTestSupport.mjs';
export { evaluate } from './moduleTestSupport.mjs';

const widgets = new Map();
export const ui = new Proxy({}, { get: (_, name) => {
  if (name === 'Table') {
    if (!widgets.has(name)) widgets.set(name, Object.assign(() => null, Object.fromEntries(['Thead', 'Tr', 'Th', 'Tbody', 'Td'].map((part) => [part, `Table.${part}`]))));
    return widgets.get(name);
  }
  return name;
} });
export const helpers = evaluate(new URL('./proposalHistory.ts', import.meta.url));
export const { ApiError, errorText } = evaluate(new URL('../api/client.ts', import.meta.url));
const same = (a, b) => !!a && !!b && a.length === b.length && a.every((v, i) => Object.is(v, b[i]));

// Run the actual page hooks and handlers with in-memory I/O; no service or target access.
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
    return [value, ...nodes(value.props?.children), ...nodes(value.props?.right), ...nodes(value.props?.action)];
  }
  const find = (predicate) => { const node = nodes(tree).find(predicate); assert.ok(node, 'Expected UI element'); return node; };
  const control = (name) => find((node) => node.props?.label === name || node.props?.['aria-label'] === name);
  const button = (name) => find((node) => node.type === 'Button' && node.props.children === name);
  return {
    settle, control, find, button, nodes: () => nodes(tree),
    async rerender(next = props) { props = next; dirty = true; await settle(); },
    async change(name, value) {
      const node = control(name); assert.ok(!node.props.disabled);
      node.props.onChange(['SegmentedControl', 'MultiSelect'].includes(node.type) ? value : { currentTarget: { value, checked: value } });
      await settle();
    },
    async click(name) { const node = button(name); assert.ok(!node.props.disabled); node.props.onClick(); await settle(); },
    unmount() { cells.forEach((cell) => cell.cleanup?.()); },
  };
}

export function browser(t, values = new Map()) {
  const cleanups = [];
  const original = { window: globalThis.window, document: globalThis.document, storage: Object.getOwnPropertyDescriptor(globalThis, 'localStorage') };
  const timers = new Map(); let next = 0;
  globalThis.window = {
    setInterval(fn) { const id = ++next; timers.set(id, fn); return id; }, clearInterval(id) { timers.delete(id); },
    setTimeout(fn) { const id = ++next; timers.set(id, () => { timers.delete(id); fn(); }); return id; }, clearTimeout(id) { timers.delete(id); },
  };
  globalThis.document = { getElementById: () => ({ scrollIntoView() {} }) };
  Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: { getItem: (key) => values.get(key) ?? null, setItem: (key, value) => values.set(key, value) } });
  t.after(() => {
    cleanups.forEach((cleanup) => cleanup());
    globalThis.window = original.window; globalThis.document = original.document;
    if (original.storage) Object.defineProperty(globalThis, 'localStorage', original.storage); else delete globalThis.localStorage;
  });
  return { values, timers, cleanup(fn) { cleanups.push(fn); }, tick() { [...timers.values()].forEach((fn) => fn()); } };
}

export const proposal = (state = 'verified', id = 'old-change') => ({
  id, state, finding_id: 'finding-one', title: 'Disable remote root login', host: 'host-id',
  target: { id: 'host-id', name: 'Web server', asset_type: 'linux', simulated: true },
  severity: 'medium', citations: [], created_at: '2026-10-28T12:00:00Z', decided_at: '2026-10-28T13:00:00Z', decided_by: 'IT1 Approver',
  history: [{ state: 'proposed', actor: 'IT1 Requester', ts: '2026-10-28T12:00:00Z' }, { state, actor: 'IT1 Operator', ts: '2026-10-29T14:00:00Z' }],
  before_state_ref: 'saved-reference', rollback_plan: 'Restore captured configuration.', fix: null, finding: null,
});
