import assert from 'node:assert/strict';
import test from 'node:test';
import { evaluate } from '../lib/moduleTestSupport.mjs';

const compile = (path) => new URL(path, import.meta.url);

const source = compile('./ProposalPlan.tsx');
const { ApiError, errorText } = evaluate(compile('../api/client.ts'));
const { actorProblem } = evaluate(compile('./ActorChip.tsx'), { '../state/AppState': {} });
const ui = new Proxy({}, { get: (_, name) => name });
const sameDeps = (a, b) => !!a && !!b && a.length === b.length && a.every((v, i) => Object.is(v, b[i]));
const response = (id = 'proposal-one', marker = 'first') => ({
  version: 1, mode: 'static', proposal_id: id, fix: { title: marker }, target: { id: 'fixture' },
});

// Same shallow hook/effect pattern as the review panel tests. Requests are deferred in memory.
function mount({ component = 'ProposalPlan', props: initialProps = {}, actor = 'IT1 Reviewer', kill = false } = {}) {
  const cells = [], requests = [];
  let index = 0, dirty = true, tree, effects = [], unmounted = false, lateWrites = 0;
  let app = { actor, status: { kill: { engaged: kill } } };
  const hooks = {
    useState(initial) {
      const cell = cells[index++] ??= { value: typeof initial === 'function' ? initial() : initial };
      return [cell.value, (update) => {
        if (unmounted) lateWrites++;
        const next = typeof update === 'function' ? update(cell.value) : update;
        if (!Object.is(next, cell.value)) { cell.value = next; dirty = true; }
      }];
    },
    useRef(initial) { return cells[index++] ??= { current: initial }; },
    useEffect(effect, deps) {
      const slot = index++;
      const previous = cells[slot];
      if (!sameDeps(previous?.deps, deps)) {
        const cell = cells[slot] = { deps, effect };
        effects.push(() => { previous?.cleanup?.(); cell.cleanup = effect(); });
      }
    },
  };
  const api = { plan: (id) => new Promise((resolve, reject) => requests.push({ id, resolve, reject })) };
  const components = evaluate(source, {
    './ProposalMaintenance': ui, react: hooks, '@mantine/core': ui, '../api/client': { api, ApiError, errorText },
    '../lib/format': { fmtZonedTime: (value) => value, label: (value) => value },
    '../state/AppState': { useAppState: () => app }, './ActorChip': { actorProblem }, './common': ui,
  });
  const props = { proposalId: 'proposal-one', opened: true, onClose() { props.opened = false; dirty = true; }, ...initialProps };
  function render() {
    dirty = false; index = 0; effects = [];
    tree = components[component](props);
    const pending = effects; effects = [];
    pending.forEach((effect) => effect());
  }
  async function settle() {
    for (let pass = 0; pass < 30; pass++) {
      if (dirty && !unmounted) render();
      await new Promise((resolve) => setImmediate(resolve));
      if (!dirty || unmounted) return;
    }
    throw new Error('Component did not settle');
  }
  function nodes(value = tree) {
    if (Array.isArray(value)) return value.flatMap((child) => nodes(child));
    if (!value || typeof value !== 'object') return [];
    return [value, ...nodes(value.props?.children ?? null)];
  }
  const findButton = (label) => nodes().find((node) => node.type === 'Button' && node.props.children === label);
  const button = (label) => { const node = findButton(label); assert.ok(node, `Expected ${label}`); return node; };
  return {
    requests, settle, button, nodes,
    async click(label) { const node = button(label); assert.ok(!node.props.disabled, `${label} is disabled`); node.props.onClick(); await settle(); },
    async setProps(next) { Object.assign(props, next); dirty = true; await settle(); },
    async setActor(actor) { app = { ...app, actor }; dirty = true; await settle(); },
    async setKill(engaged) { app = { ...app, status: { kill: { engaged } } }; dirty = true; await settle(); },
    async closeModal() { nodes().find((node) => node.type === 'Modal').props.onClose(); await settle(); },
    view() { return nodes().find((node) => node.type === components.ProposalPlanView)?.props.plan; },
    alert(title) { return nodes().find((node) => node.type === 'Alert' && node.props.title === title); },
    async replayEffects() { cells.forEach((cell) => { if (cell.effect) { cell.cleanup?.(); cell.cleanup = cell.effect(); } }); await settle(); },
    unmount() { cells.forEach((cell) => cell.cleanup?.()); unmounted = true; },
    lateWrites: () => lateWrites,
  };
}

test('opening and repeated effects do not request; explicit click loads once and refresh discards old data', async () => {
  const panel = mount();
  await panel.settle();
  await panel.replayEffects();
  assert.equal(panel.requests.length, 0);
  const click = panel.button('Request preview').props.onClick;
  click(); click();
  await panel.settle();
  assert.equal(panel.requests.length, 1, 'Rapid duplicate clicks must not duplicate an audited POST');
  assert.equal(panel.requests[0].id, 'proposal-one');
  assert.equal(panel.button('Requesting preview').props.loading, true);
  assert.equal(panel.button('Requesting preview').props.disabled, true);
  assert.equal(panel.view(), undefined);
  panel.requests[0].resolve(response());
  await panel.settle();
  assert.equal(panel.view().fix.title, 'first');
  await panel.click('Refresh preview');
  assert.equal(panel.view(), undefined, 'Do not display the previous plan as a fresh result');
  panel.requests[1].resolve(response('proposal-one', 'refreshed'));
  await panel.settle();
  assert.equal(panel.view().fix.title, 'refreshed');
  panel.unmount();
});

for (const status of [0, 403, 409, 500, 404, 405, 501]) {
  test(`request error ${status} displays detail, classifies unavailable, and allows explicit retry`, async () => {
    const panel = mount();
    await panel.settle();
    await panel.click('Request preview');
    panel.requests[0].reject(new ApiError(status, `Server detail ${status}`));
    await panel.settle();
    const title = [404, 405, 501].includes(status) ? 'Preview not available' : 'Preview request failed';
    assert.equal(panel.alert(title).props.children.props.children, `Server detail ${status}`);
    assert.equal(panel.view(), undefined);
    await panel.click('Retry preview');
    panel.requests[1].resolve(response());
    await panel.settle();
    assert.ok(panel.view());
    panel.unmount();
  });
}

test('a failed refresh removes the previous result and supports retry', async () => {
  const panel = mount();
  await panel.settle(); await panel.click('Request preview');
  panel.requests[0].resolve(response()); await panel.settle();
  await panel.click('Refresh preview');
  panel.requests[1].reject(new Error('Connection lost')); await panel.settle();
  assert.equal(panel.view(), undefined);
  assert.ok(panel.alert('Preview request failed'));
  assert.ok(panel.button('Retry preview'));
  panel.unmount();
});

for (const outcome of ['resolve', 'reject']) {
  test(`old ${outcome} after proposal ID changes cannot replace the new pending request or result`, async () => {
    const panel = mount();
    await panel.settle(); await panel.click('Request preview');
    await panel.setProps({ proposalId: 'proposal-two' });
    assert.equal(panel.view(), undefined);
    assert.equal(panel.requests.length, 1, 'An ID change must not make an audited POST');
    await panel.click('Request preview');
    panel.requests[0][outcome](outcome === 'resolve' ? response() : new Error('Old error'));
    await panel.settle();
    assert.equal(panel.button('Requesting preview').props.disabled, true);
    panel.requests[1].resolve(response('proposal-two', 'second')); await panel.settle();
    assert.equal(panel.view().proposal_id, 'proposal-two');
    assert.equal(panel.view().fix.title, 'second');
    panel.unmount();
  });
}

for (const close of ['button', 'modal', 'prop', 'unmount']) {
  for (const outcome of ['resolve', 'reject']) {
    test(`${close} discards late ${outcome} and reopening requires a new explicit request`, async () => {
      const panel = mount();
      await panel.settle(); await panel.click('Request preview');
      if (close === 'button') await panel.click('Close');
      else if (close === 'modal') await panel.closeModal();
      else if (close === 'prop') await panel.setProps({ opened: false });
      else panel.unmount();
      if (close !== 'unmount') { await panel.setProps({ opened: true }); await panel.click('Request preview'); }
      panel.requests[0][outcome](outcome === 'resolve' ? response() : new Error('Old error'));
      await panel.settle();
      if (close === 'unmount') assert.equal(panel.lateWrites(), 0);
      else {
        assert.equal(panel.view(), undefined);
        assert.equal(panel.button('Requesting preview').props.disabled, true);
        panel.requests[1].resolve(response('proposal-one', 'reopened')); await panel.settle();
        assert.equal(panel.view().fix.title, 'reopened');
        panel.unmount();
      }
    });
  }
}

test('closing a completed preview clears it; changing ID clears a completed preview', async () => {
  const panel = mount();
  await panel.settle(); await panel.click('Request preview');
  panel.requests[0].resolve(response()); await panel.settle();
  await panel.click('Close'); await panel.setProps({ opened: true });
  assert.equal(panel.view(), undefined);
  assert.ok(panel.button('Request preview'));
  await panel.click('Request preview');
  panel.requests[1].resolve(response()); await panel.settle();
  await panel.setProps({ proposalId: 'proposal-two' });
  assert.equal(panel.view(), undefined);
  assert.ok(panel.button('Request preview'));
  panel.unmount();
});

test('unsupported or missing preview and mismatched proposal are never shown as valid results', async () => {
  for (const [value, title] of [
    [null, 'Preview not available'], [responseWith({ version: 2 }), 'Preview not available'],
    [responseWith({ mode: 'execution' }), 'Preview not available'], [responseWith({ fix: null }), 'Preview not available'],
    [responseWith({ target: null }), 'Preview not available'], [response('different'), 'Preview request failed'],
  ]) {
    const panel = mount();
    await panel.settle(); await panel.click('Request preview');
    panel.requests[0].resolve(value); await panel.settle();
    assert.equal(panel.view(), undefined); assert.ok(panel.alert(title));
    panel.unmount();
  }
});
function responseWith(fields) { return { ...response(), ...fields }; }

for (const actor of ['', '  ', 'system', 'agent', 'llm', 'policy:rule', 'x'.repeat(129)]) {
  test(`invalid actor ${JSON.stringify(actor.slice(0, 20))} blocks both opening and requesting`, async () => {
    for (const component of ['PreviewButton', 'ProposalPlan']) {
      const panel = mount({ component, actor });
      await panel.settle();
      const node = panel.button(component === 'PreviewButton' ? 'Preview change' : 'Request preview');
      assert.equal(node.props.disabled, true);
      node.props.onClick(); await panel.settle();
      assert.equal(panel.requests.length, 0);
      if (component === 'PreviewButton') assert.equal(panel.nodes().find((node) => typeof node.type === 'function' && node.type.name === 'ProposalPlan').props.opened, false);
      panel.unmount();
    }
  });
}

test('busy and kill switch block opening and requests without adding a proposal state restriction', async () => {
  for (const component of ['PreviewButton', 'ProposalPlan']) {
    const panel = mount({ component }); await panel.settle();
    const label = component === 'PreviewButton' ? 'Preview change' : 'Request preview';
    assert.equal(panel.button(label).props.disabled, false);
    await panel.setProps({ busy: true }); assert.equal(panel.button(label).props.disabled, true);
    panel.button(label).props.onClick(); await panel.settle(); assert.equal(panel.requests.length, 0);
    await panel.setProps({ busy: false }); await panel.setKill(true);
    assert.equal(panel.button(label).props.disabled, true);
    panel.button(label).props.onClick(); await panel.settle(); assert.equal(panel.requests.length, 0);
    await panel.setKill(false); assert.equal(panel.button(label).props.disabled, false);
    panel.unmount();
  }
});

test('actor and kill changes while open gate refresh and retry; closing remains possible', async () => {
  const panel = mount(); await panel.settle(); await panel.click('Request preview');
  panel.requests[0].resolve(response()); await panel.settle();
  await panel.setActor(''); assert.equal(panel.button('Refresh preview').props.disabled, true);
  panel.button('Refresh preview').props.onClick(); await panel.settle(); assert.equal(panel.requests.length, 1);
  await panel.setActor('IT1 Reviewer'); await panel.click('Refresh preview');
  panel.requests[1].reject(new Error('Failed')); await panel.settle();
  await panel.setKill(true); assert.equal(panel.button('Retry preview').props.disabled, true);
  panel.button('Retry preview').props.onClick(); await panel.settle(); assert.equal(panel.requests.length, 2);
  await panel.click('Close');
  panel.unmount();
});

test('Preview change opens only its current proposal and never starts a request itself', async () => {
  const panel = mount({ component: 'PreviewButton' }); await panel.settle();
  const modal = () => panel.nodes().find((node) => typeof node.type === 'function' && node.type.name === 'ProposalPlan');
  assert.equal(modal().props.opened, false);
  await panel.click('Preview change'); assert.equal(modal().props.opened, true);
  await panel.setProps({ proposalId: 'proposal-two' }); assert.equal(modal().props.opened, false);
  await panel.setProps({ proposalId: 'proposal-one' }); assert.equal(modal().props.opened, false);
  assert.equal(panel.requests.length, 0);
  panel.unmount();
});
