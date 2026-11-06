import assert from 'node:assert/strict';
import test from 'node:test';
import { actorProblem, errorText, evaluate, mount, target, ui } from '../lib/setupTestSupport.mjs';

const preview = (overrides = {}) => ({ networks: ['10.20.30.40/32'], network_count: 1, input_address_count: '1',
  excluded_address_count: '0', address_count: '1', truncated: false, can_save: true, blocking_reasons: [], warnings: [],
  normalizations: [], requires_normalization_acknowledgment: false,
  limits: { max_entries: 128, max_networks: 256, max_addresses: 65536 }, ...overrides });
const scope = (overrides = {}) => ({ cidr: '10.20.30.40/32', allow_public: false, scanner_target: null, added_by: 'IT1 Operator',
  added_at: '2026-11-05T12:00:00Z', reason: 'Existing authorization to search', ...overrides });

const recipe = (overrides = {}) => ({ id: 'range-a', name: 'Enclave A', include: ['10.20.30.40'], exclude: [],
  allow_public: false, scanner_target: null, acknowledge_normalization: false, networks: ['10.20.30.40/32'],
  original_expressions_known: true, ...overrides });
const bodyOf = (row) => Object.fromEntries(Object.entries(row).filter(([key]) => !['networks', 'original_expressions_known'].includes(key)));

async function setup(t, current = [], recipes = null) {
  const requests = [], busy = [], loads = [];
  let loaded = { revision: 'revision-1', scopes: current, recipes: recipes ?? current.map((s, i) => recipe({ id: `range-${i}`, name: `Range ${i + 1}`,
    include: [s.cidr], networks: [s.cidr], allow_public: s.allow_public, scanner_target: s.scanner_target })) };
  let loadFailure = null;
  let saved = 0, closed = 0;
  const ctx = { actor: 'IT1 Operator', status: { kill: { engaged: false } }, statusError: null };
  const props = { current, onSaved: () => saved++, onClose: () => closed++, setBusy: (value) => busy.push(value) };
  const api = new Proxy({
    targets: async () => ({ targets: [target({ in_scope: true })] }),
  }, { get(object, name) { assert.ok(name in object, `Unexpected operation: ${String(name)}`); return object[name]; } });
  const scopeRecipesApi = {
    load: async () => { loads.push(true); if (loadFailure) throw loadFailure; return structuredClone(loaded); },
    preview: (arg) => new Promise((resolve, reject) => requests.push({ kind: 'preview', arg, resolve, reject })),
    save: (arg) => new Promise((resolve, reject) => requests.push({ kind: 'save', arg, resolve, reject })),
  };
  const panel = mount((hooks) => evaluate(new URL('./ScopeEditor.tsx', import.meta.url), {
    react: hooks, '@mantine/core': ui, '../api/client': { api, errorText }, '../api/scopeRecipes': { scopeRecipesApi }, './common': ui,
    './setupAccess': evaluate(new URL('./setupAccess.ts', import.meta.url), {
      '../state/AppState': { useAppState: () => ctx }, './ActorChip': { actorProblem },
    }),
  }).ScopeEditorContent, props);
  t.after(() => panel.unmount());
  await panel.settle();
  return { ...panel, requests, loads, ctx, busy,
    setLoad(value) { loaded = value; loadFailure = null; },
    failLoad(error) { loadFailure = error; }, saved: () => saved, closed: () => closed,
    async update(next) { Object.assign(props, next); await panel.rerender(props); },
    async respond(value = preview(), index = requests.length - 1) {
      const req = requests[index];
      req.resolve(req.kind === 'preview' ? { revision: req.arg.revision, fingerprint: 'f'.repeat(64), preview: value,
        recipes: req.arg.recipes.map((r) => ({ id: r.id, name: r.name, preview: value })) } : value);
      await panel.settle();
    },
    async confirm() {
      await panel.change('Search range decision reason', 'Reviewed by network owner');
      await panel.change('I reviewed the exact effective search ranges and exclusions; inventory authorization stays unchanged', true);
    },
  };
}

function assertBlocked(panel) {
  assert.equal(panel.button('Confirm search ranges').props.disabled, true);
  const before = panel.requests.length;
  panel.button('Confirm search ranges').props.onClick();
  assert.equal(panel.requests.length, before, 'No mutation from a blocked direct handler');
}

test('mixed IPv4/IPv6 single IP, CIDR and inclusive ranges reach only an explicit server preview', async (t) => {
  const panel = await setup(t);
  assert.equal(panel.requests.length, 0);
  await panel.change('Search addresses or ranges', '10.20.30.40, 10.20.30.50 - 10.20.30.60\nfd00::1\nfd00::10/124');
  await panel.change('Exclude addresses or ranges', '10.20.30.55\nfd00::12-fd00::13');
  await panel.click('Preview exact search ranges');
  assert.equal(panel.requests[0].arg.revision, 'revision-1');
  assert.deepEqual(panel.requests[0].arg.recipes[0], { id: 'range-new', name: 'New recipe',
    include: ['10.20.30.40', '10.20.30.50 - 10.20.30.60', 'fd00::1', 'fd00::10/124'],
    exclude: ['10.20.30.55', 'fd00::12-fd00::13'], allow_public: false, scanner_target: null, acknowledge_normalization: false,
  });
  assertBlocked(panel);
  await panel.respond(); assertBlocked(panel);
  assert.equal(panel.saved(), 0);
});

test('saving exact input/exclusion choices requires a reason and review; it never accepts assets or starts a sweep', async (t) => {
  const panel = await setup(t);
  await panel.change('Search addresses or ranges', '10.20.30.1-10.20.30.4');
  await panel.change('Exclude addresses or ranges', '10.20.30.2');
  await panel.click('Preview exact search ranges'); await panel.respond(preview({ address_count: '3' }));
  await panel.confirm();
  const click = panel.button('Confirm search ranges').props.onClick;
  click(); click(); await panel.settle();
  assert.equal(panel.requests.length, 2);
  assert.equal(panel.requests[1].arg.preview_fingerprint, 'f'.repeat(64));
  assert.equal(panel.requests[1].arg.reason, 'Reviewed by network owner');
  assert.deepEqual(panel.requests[1].arg.recipes[0], { id: 'range-new', name: 'New recipe', include: ['10.20.30.1-10.20.30.4'], exclude: ['10.20.30.2'],
    allow_public: false, scanner_target: null, acknowledge_normalization: false });
  assert.equal(panel.requests[1].kind, 'save');
  await panel.respond({ scopes: [scope()], preview: preview() });
  assert.equal(panel.saved(), 1); assert.equal(panel.closed(), 1);
});

test('CIDR broadening needs an explicit acknowledgement, a new preview and the same acknowledgement on save', async (t) => {
  const panel = await setup(t);
  await panel.change('Search addresses or ranges', '10.20.30.40/24');
  await panel.click('Preview exact search ranges');
  const normalized = { networks: ['10.20.30.0/24'], address_count: '256', input_address_count: '256',
    normalizations: [{ field: 'include', input: '10.20.30.40/24', normalized: '10.20.30.0/24' }], requires_normalization_acknowledgment: true };
  await panel.respond(preview({ ...normalized, can_save: false, blocking_reasons: ['host-bit CIDR normalization requires acknowledge_normalization=true for these submitted inputs'] }));
  await panel.confirm(); assertBlocked(panel);
  await panel.change('I acknowledge the listed CIDR broadening for these exact inputs', true);
  assertBlocked(panel);
  await panel.click('Preview exact search ranges');
  assert.equal(panel.requests[1].arg.recipes[0].acknowledge_normalization, true);
  await panel.respond(preview(normalized)); await panel.confirm();
  assert.equal(panel.button('Confirm search ranges').props.disabled, false);
  await panel.click('Confirm search ranges');
  assert.equal(panel.requests[2].arg.recipes[0].acknowledge_normalization, true);
  assert.deepEqual(panel.requests[2].arg.recipes[0].include, ['10.20.30.40/24']);
  panel.requests[2].reject(new Error('Temporary refusal')); await panel.settle();
  await panel.change('Exclude addresses or ranges', '10.20.30.0/25');
  assertBlocked(panel);
  assert.ok(!panel.nodes().some((node) => node.props?.preview));
  await panel.click('Preview exact search ranges');
  assert.equal(panel.requests[3].arg.recipes[0].acknowledge_normalization, false, 'Changed exclusions revoke the previous broadening acknowledgement');
});

test('additional range warnings require review independently of normalization acknowledgement', async (t) => {
  const panel = await setup(t);
  await panel.click('Preview exact search ranges'); await panel.respond(preview({ warnings: ['exclusions do not intersect the included scope'] }));
  await panel.confirm(); assertBlocked(panel);
  await panel.change('I acknowledge the additional range warnings', true);
  assert.equal(panel.button('Confirm search ranges').props.disabled, false);
});

for (const [name, result] of [
  ['huge IPv6 scope', preview({ address_count: '340282366920938463463374607431768211456', can_save: false, blocking_reasons: ['effective scope exceeds 65536 total addresses'] })],
  ['truncated preview', preview({ truncated: true, network_count: 257 })],
  ['entirely excluded include', preview({ address_count: '0', networks: [], can_save: false, blocking_reasons: ['exclusions remove the entire included scope'] })],
  ['inconsistent blocker response', preview({ blocking_reasons: ['Scope policy refused'] })],
  ['missing normalization contract', preview({ normalizations: undefined, requires_normalization_acknowledgment: undefined })],
]) {
  test(`${name} stays blocked after acknowledgement`, async (t) => {
    const panel = await setup(t);
    await panel.click('Preview exact search ranges'); await panel.respond(result); await panel.confirm();
    assertBlocked(panel);
  });
}

test('empty inputs clear only after preview and explicit confirmation', async (t) => {
  const panel = await setup(t, [scope()]);
  await panel.change('Search addresses or ranges', '');
  await panel.click('Preview exact search ranges');
  await panel.respond(preview({ networks: [], network_count: 0, address_count: '0', input_address_count: '0' }));
  assertBlocked(panel); await panel.confirm(); await panel.click('Confirm search ranges');
  assert.deepEqual(panel.requests[1].arg.recipes[0].include, []);
  assert.equal(panel.requests[1].kind, 'save');
});

test('preview is read-only without an actor, while actor/kill changes block saving the reviewed result', async (t) => {
  const panel = await setup(t);
  panel.ctx.actor = ''; await panel.rerender();
  await panel.click('Preview exact search ranges'); await panel.respond(); await panel.confirm(); assertBlocked(panel);
  panel.ctx.actor = 'IT1 Operator'; panel.ctx.status.kill.engaged = true; await panel.rerender(); assertBlocked(panel);
  panel.ctx.status.kill.engaged = false; panel.ctx.statusError = 'Status unavailable'; await panel.rerender(); assertBlocked(panel);
  panel.ctx.statusError = null; await panel.rerender();
  assert.equal(panel.button('Confirm search ranges').props.disabled, false);
});

test('homogeneous saved public/scanner declarations and scanner aliases are preserved', async (t) => {
  const panel = await setup(t, [scope({ allow_public: true, scanner_target: 'fixture-host' })]);
  assert.equal(panel.control('Scanner vantage point').props.value, 'fixture-host');
  assert.ok(panel.control('Scanner vantage point').props.data.some((row) => row.label === 'Existing alias (fixture-host)'));
  await panel.click('Preview exact search ranges'); await panel.respond(); await panel.confirm(); await panel.click('Confirm search ranges');
  assert.equal(panel.requests[1].arg.recipes[0].scanner_target, 'fixture-host');
  assert.equal(panel.requests[1].arg.recipes[0].allow_public, true);
});

test('editing one recipe preserves other expressions and differing scanner/public policies', async (t) => {
  const second = recipe({ id: 'range-b', name: 'Enclave B', include: ['203.0.113.8'], exclude: ['203.0.113.9'], allow_public: true, scanner_target: 'fixture-host' });
  const panel = await setup(t, [], [recipe(), second]);
  await panel.change('Search addresses or ranges', '10.20.30.41');
  await panel.click('Preview exact search ranges'); await panel.respond(); await panel.confirm();
  await panel.click('Confirm search ranges');
  assert.deepEqual(panel.requests[1].arg.recipes[1], bodyOf(second));
  assert.deepEqual(panel.requests[1].arg.recipes[0].include, ['10.20.30.41']);
});

test('public range permission is explicit and changing it invalidates the current preview', async (t) => {
  const panel = await setup(t);
  assert.equal(panel.control('Allow public address space in this reviewed selection').props.checked, false);
  await panel.change('Search addresses or ranges', '203.0.113.8');
  await panel.click('Preview exact search ranges'); await panel.respond(preview({ can_save: false, blocking_reasons: ['public address space requires explicit allow_public'] }));
  await panel.change('Allow public address space in this reviewed selection', true); assertBlocked(panel);
  await panel.click('Preview exact search ranges');
  assert.equal(panel.requests[1].arg.recipes[0].allow_public, true);
});

test('preview/save failures stay visible and never report saved; late results after close are ignored', async (t) => {
  const panel = await setup(t);
  await panel.click('Preview exact search ranges'); panel.requests[0].reject(new Error('Invalid range')); await panel.settle();
  assertBlocked(panel);
  assert.equal(panel.find((node) => node.type === 'ErrorBox').props.error, 'Invalid range');
  await panel.click('Preview exact search ranges'); await panel.respond(); await panel.confirm(); await panel.click('Confirm search ranges');
  panel.requests[2].reject(new Error('Scope save refused')); await panel.settle();
  assert.equal(panel.saved(), 0); assert.equal(panel.closed(), 0);
  assert.equal(panel.find((node) => node.type === 'ErrorBox').props.error, 'Scope save refused');
  await panel.click('Preview exact search ranges'); panel.unmount(); await panel.respond();
  assert.equal(panel.lateWrites(), 0);
});

test('oversized inputs are refused without sending a request and concurrent saved-scope changes require reopening', async (t) => {
  const panel = await setup(t);
  await panel.change('Search addresses or ranges', Array(129).fill('10.20.30.40').join('\n'));
  assert.equal(panel.button('Preview exact search ranges').props.disabled, true);
  panel.button('Preview exact search ranges').props.onClick(); assert.equal(panel.requests.length, 0);
  await panel.change('Search addresses or ranges', '10.20.30.40');
  await panel.click('Preview exact search ranges'); await panel.respond(); await panel.confirm();
  await panel.update({ current: [scope()] }); assertBlocked(panel);
  assert.equal(panel.button('Preview exact search ranges').props.disabled, true);
});

test('reload restores original exclusions and reset drops local edits without writing or trusting a prior preview', async (t) => {
  const original = recipe({ name: 'Réseau 北', include: ['10.20.30.1-10.20.30.9'], exclude: ['10.20.30.4'] });
  const panel = await setup(t, [], [original]);
  assert.equal(panel.control('Exclude addresses or ranges').props.value, '10.20.30.4');
  await panel.change('Exclude addresses or ranges', '10.20.30.5');
  await panel.click('Preview exact search ranges'); await panel.respond(); await panel.confirm();
  await panel.click('Reset unsaved edits');
  assert.equal(panel.control('Exclude addresses or ranges').props.value, '10.20.30.4');
  assertBlocked(panel);
  panel.setLoad({ revision: 'revision-2', scopes: [], recipes: [recipe({ name: 'Other operator edit', exclude: ['10.20.30.6'] })] });
  await panel.click('Reload saved recipes');
  assert.equal(panel.control('Recipe name').props.value, 'Other operator edit');
  assert.equal(panel.control('Exclude addresses or ranges').props.value, '10.20.30.6');
  await panel.click('Preview exact search ranges');
  assert.equal(panel.requests[1].arg.revision, 'revision-2');
  assert.equal(panel.requests.filter((r) => r.kind === 'save').length, 0);
});

test('legacy records show unknown originals and require explicit conversion before expression editing', async (t) => {
  const legacy = recipe({ include: null, exclude: null, original_expressions_known: false, scanner_target: 'fixture-host', allow_public: true });
  const panel = await setup(t, [], [legacy]);
  assert.equal(panel.nodes().some((n) => n.props?.label === 'Search addresses or ranges'), false);
  assert.ok(panel.nodes().some((n) => typeof n.props?.children === 'string' && n.props.children.includes('Original include/exclude expressions are unknown')));
  await panel.click('Preview exact search ranges');
  assert.equal(panel.requests[0].arg.recipes[0].include, null);
  await panel.respond();
  await panel.click('Use effective ranges as new expressions');
  assert.equal(panel.control('Search addresses or ranges').props.value, '10.20.30.40/32');
  assert.equal(panel.control('Exclude addresses or ranges').props.value, '');
  assert.equal(panel.control('Scanner vantage point').props.value, 'fixture-host');
  assert.equal(panel.control('Allow public address space in this reviewed selection').props.checked, true);
  assertBlocked(panel);
  await panel.click('Reset unsaved edits');
  assert.equal(panel.nodes().some((n) => n.props?.label === 'Search addresses or ranges'), false);
});

test('adding, switching and removing recipes keep per-range policies and invalidate pending confirmation', async (t) => {
  const panel = await setup(t, [], [recipe({ exclude: ['10.20.30.41'] })]);
  await panel.click('Add recipe');
  await panel.change('Recipe name', 'Réseau B');
  await panel.change('Search addresses or ranges', 'fd00::1-fd00::8');
  await panel.change('Exclude addresses or ranges', 'fd00::4');
  await panel.change('Scanner vantage point', 'fixture-host');
  await panel.change('Recipe to edit', 'range-a');
  assert.equal(panel.control('Exclude addresses or ranges').props.value, '10.20.30.41');
  assert.equal(panel.control('Scanner vantage point').props.value, '');
  await panel.click('Preview exact search ranges'); await panel.respond(); await panel.confirm();
  assert.deepEqual(panel.requests[0].arg.recipes[1].exclude, ['fd00::4']);
  assert.equal(panel.requests[0].arg.recipes[1].scanner_target, 'fixture-host');
  await panel.click('Remove selected recipe');
  assertBlocked(panel);
  assert.equal(panel.control('Recipe name').props.value, 'Réseau B');
  await panel.click('Preview exact search ranges');
  assert.equal(panel.requests[1].arg.recipes.length, 1);
});

test('server revision conflict requires reload and does not discard the other operator change', async (t) => {
  const panel = await setup(t, [], [recipe()]);
  await panel.click('Preview exact search ranges'); await panel.respond(); await panel.confirm(); await panel.click('Confirm search ranges');
  panel.requests[1].reject(Object.assign(new Error('Saved search recipes changed'), { status: 409 })); await panel.settle();
  assertBlocked(panel);
  assert.equal(panel.button('Preview exact search ranges').props.disabled, true);
  await panel.click('Reset unsaved edits');
  assert.equal(panel.button('Preview exact search ranges').props.disabled, true, 'Local reset cannot clear a server conflict');
  panel.setLoad({ revision: 'revision-2', scopes: [], recipes: [recipe({ scanner_target: 'fixture-host' })] });
  await panel.click('Reload saved recipes');
  await panel.click('Preview exact search ranges');
  assert.equal(panel.requests[2].arg.revision, 'revision-2');
  assert.equal(panel.requests[2].arg.recipes[0].scanner_target, 'fixture-host');
});

test('failed reload leaves saving blocked and malformed preview revision cannot bind', async (t) => {
  const panel = await setup(t, [], [recipe()]);
  panel.failLoad(new Error('Recipe load unavailable'));
  await panel.click('Reload saved recipes');
  assertBlocked(panel);
  assert.equal(panel.button('Preview exact search ranges').props.disabled, true);
  panel.setLoad({ revision: 'revision-2', scopes: [], recipes: [recipe()] });
  await panel.click('Reload saved recipes'); await panel.click('Preview exact search ranges');
  panel.requests[0].resolve({ revision: 'wrong-revision', fingerprint: 'f'.repeat(64), preview: preview(), recipes: [] });
  await panel.settle(); await panel.confirm(); assertBlocked(panel);
});

test('Unicode expressions reach server validation unchanged and refusal remains visible', async (t) => {
  const panel = await setup(t);
  await panel.change('Search addresses or ranges', '１０.20.30.40');
  await panel.click('Preview exact search ranges');
  assert.deepEqual(panel.requests[0].arg.recipes[0].include, ['１０.20.30.40']);
  panel.requests[0].reject(new Error('scope entries must use ASCII IP syntax')); await panel.settle();
  assertBlocked(panel);
  assert.equal(panel.find((n) => n.type === 'ErrorBox').props.error, 'scope entries must use ASCII IP syntax');
});

test('unchanged expression formatting survives editing another recipe and Unicode whitespace is not silently removed', async (t) => {
  const original = recipe({ include: [' 10.20.30.1 - 10.20.30.9 '], exclude: [' 10.20.30.4 '] });
  const panel = await setup(t, [], [original, recipe({ id: 'range-b' })]);
  await panel.change('Recipe to edit', 'range-b');
  await panel.change('Search addresses or ranges', '\u00a010.20.30.40');
  await panel.click('Preview exact search ranges');
  assert.deepEqual(panel.requests[0].arg.recipes[0], bodyOf(original));
  assert.deepEqual(panel.requests[0].arg.recipes[1].include, ['\u00a010.20.30.40']);
});
