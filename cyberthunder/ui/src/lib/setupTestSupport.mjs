import assert from 'node:assert/strict';
import { evaluate } from './moduleTestSupport.mjs';
export { evaluate } from './moduleTestSupport.mjs';

const widgets = new Map();
export const ui = new Proxy({}, { get: (_, name) => {
  const parts = { Radio: ['Group'], Table: ['Thead', 'Tr', 'Th', 'Tbody', 'Td'], Tabs: ['List', 'Tab', 'Panel'], Menu: ['Target', 'Dropdown', 'Item'] }[name];
  if (!parts) return name;
  if (!widgets.has(name)) widgets.set(name, Object.assign(() => null, Object.fromEntries(parts.map((part) => [part, `${name}.${part}`]))));
  return widgets.get(name);
} });

export const types = evaluate(new URL('../api/types.ts', import.meta.url));
export const { errorText, ApiError } = evaluate(new URL('../api/client.ts', import.meta.url));
export const { actorProblem } = evaluate(new URL('../components/ActorChip.tsx', import.meta.url), { '@mantine/core': ui, '../state/AppState': {} });
const same = (a, b) => !!a && !!b && a.length === b.length && a.every((v, i) => Object.is(v, b[i]));

/** Exercise the real handlers/effects with deferred in-memory I/O; never start a service or network request. */
export function mount(factory, initialProps = {}) {
  const cells = [];
  let index = 0, dirty = true, tree, effects = [], props = initialProps, unmounted = false, lateWrites = 0;
  const hooks = {
    useState(initial) {
      const cell = cells[index++] ??= { value: typeof initial === 'function' ? initial() : initial };
      cell.set ??= (update) => {
        if (unmounted) { lateWrites++; return; }
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
    for (let pass = 0; pass < 40; pass++) {
      if (dirty && !unmounted) {
        dirty = false; index = 0; effects = [];
        tree = component(props);
        effects.forEach((effect) => effect());
      }
      await new Promise((resolve) => setImmediate(resolve));
      if (!dirty || unmounted) return;
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
    settle, control, find, button, nodes: () => nodes(tree), lateWrites: () => lateWrites,
    async rerender(next = props) { props = next; dirty = true; await settle(); },
    async change(name, value) {
      const node = control(name); assert.ok(!node.props.disabled);
      node.props.onChange(['Select', 'Radio.Group', 'SegmentedControl', 'MultiSelect', 'NumberInput', 'TagsInput'].includes(node.type)
        ? value : { currentTarget: { value, checked: value } });
      await settle();
    },
    async click(name) { const node = button(name); assert.ok(!node.props.disabled, `${name} disabled`); node.props.onClick(); await settle(); },
    async submit() { find((node) => node.type === 'form').props.onSubmit({ preventDefault() {} }); await settle(); },
    unmount() { cells.forEach((cell) => cell.cleanup?.()); unmounted = true; },
  };
}

export const target = (overrides = {}) => ({
  id: 'fixture-host', name: 'Existing alias', asset_type: 'linux', transport: 'ssh', address: '10.20.30.40',
  port: 22, username: 'operator', credential_ref: 'FIXTURE_KEY', sudo: true, tags: ['production'], in_scope: false,
  simulated: false, options: { critical_services: ['sshd'], custom_declaration: 'keep-me' }, notes: 'Original notes',
  last_scan: null, added_at: '2026-11-05T12:00:00Z', ...overrides,
});
