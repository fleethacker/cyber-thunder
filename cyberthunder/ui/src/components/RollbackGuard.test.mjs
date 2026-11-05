import assert from 'node:assert/strict';
import test from 'node:test';
import { errorText, evaluate, helpers, mount, proposal, ui } from '../lib/rollbackTestSupport.mjs';

const guard = (overrides = {}) => ({
  status: 'not_checked', coverage: 'files', live_checked: false, identity_bound: true,
  transition_allowed: true, reasons: [], limitations: ['External writers are not locked.'],
  conflicting_proposals: [], last_preflight: null, ...overrides,
});
const diff = (id = 'old-change', rollback_guard = guard()) => ({
  proposal: { id }, rollback_guard, apply: { ok: true }, verify: { ok: true }, rollback: null,
  files: [{ path: '/fixture/config', before_excerpt: 'before', after_excerpt: 'after', diff: '-before\n+after' }],
});

async function setup(t, { component = 'RollbackConfirmation', props: initial = {} } = {}) {
  const requests = [];
  let confirmations = 0, closes = 0, components;
  const props = {
    proposal: proposal(), proposalId: 'old-change', state: 'verified',
    busy: false, blockedReason: null, error: null,
    onConfirm: () => confirmations++, onClose: () => closes++, ...initial,
  };
  const panel = mount((hooks) => {
    // Only the static GET is available. Any mutation, model or live lookup is a test failure.
    const api = new Proxy({ diff: (id) => new Promise((resolve, reject) => requests.push({ id, resolve, reject })) }, {
      get(target, name) { assert.ok(name in target, `Unexpected API operation: ${String(name)}`); return target[name]; },
    });
    components = evaluate(new URL('./ProposalDiff.tsx', import.meta.url), {
      react: hooks, '@mantine/core': ui, '@tabler/icons-react': ui, 'react-router-dom': ui,
      '../api/client': { api, errorText }, '../lib/format': { fmtZonedTime: (value) => value },
      '../lib/proposalHistory': helpers, './common': ui,
    });
    if (component !== 'RollbackConfirmation') return components[component];
    return evaluate(new URL('./RollbackConfirmation.tsx', import.meta.url), {
      '@mantine/core': ui, '../lib/format': { fmtZonedTime: (value) => value },
      '../lib/proposalHistory': helpers, './ProposalDiff': components, './common': ui,
    }).RollbackConfirmation;
  }, props);
  t.after(() => panel.unmount());
  await panel.settle();
  return {
    ...panel, requests, components, confirmations: () => confirmations, closes: () => closes,
    async update(next) { Object.assign(props, next); await panel.rerender(props); },
    async respond(index = requests.length - 1, value = diff(requests[index].id)) { requests[index].resolve(value); await panel.settle(); },
    async fail(index = requests.length - 1) { requests[index].reject(new Error('Static lookup failed')); await panel.settle(); },
    guardView: () => panel.find((node) => node.type === components.RollbackGuardView).props,
  };
}

function assertBlocked(panel) {
  assert.equal(panel.button('Confirm rollback').props.disabled, true);
  const before = panel.confirmations();
  panel.button('Confirm rollback').props.onClick();
  assert.equal(panel.confirmations(), before, 'The handler must also enforce the disabled state');
}

test('confirmation fetches only on explicit open and blocks until current static checks arrive', async (t) => {
  const panel = await setup(t, { props: { proposal: null } });
  assert.equal(panel.requests.length, 0);
  await panel.update({ proposal: proposal() });
  assert.deepEqual(panel.requests.map((r) => r.id), ['old-change']);
  assertBlocked(panel);
  assert.ok(panel.nodes().some((node) => node.props?.what === 'Loading current static rollback checks'));
  await panel.respond();
  assert.equal(panel.button('Confirm rollback').props.disabled, false);
  assert.equal(panel.confirmations(), 0);
  await panel.click('Confirm rollback');
  assert.equal(panel.confirmations(), 1);
  assert.equal(panel.requests.length, 1);
  const text = panel.nodes().map((node) => typeof node.props?.children === 'string' ? node.props.children : '').join(' ');
  for (const phrase of ['may overwrite newer external work', 'may restore the original vulnerability',
    'saved diff does not inspect the live target', 'run a fresh scan']) assert.ok(text.includes(phrase), phrase);
});

test('current actor, kill, busy and proposal eligibility still block direct confirmation handlers', async (t) => {
  const panel = await setup(t);
  await panel.respond();
  for (const change of [
    { blockedReason: 'Enter your acting name' },
    { blockedReason: 'Kill switch engaged' },
    { blockedReason: null, busy: true },
    { busy: false, proposal: proposal('failed') },
    { proposal: proposal('rolled_back') },
  ]) {
    await panel.update(change);
    assertBlocked(panel);
  }
  assert.equal(panel.requests.length, 1, 'Parent state refreshes must not connect or refetch unnecessarily');
});

test('busy confirmation cannot close or navigate through either conflict view', async (t) => {
  const panel = await setup(t);
  await panel.respond();
  await panel.update({ busy: true });
  const modal = panel.find((node) => node.type === 'Modal');
  assert.equal(modal.props.closeOnClickOutside, false);
  assert.equal(modal.props.closeOnEscape, false);
  assert.equal(modal.props.withCloseButton, false);
  modal.props.onClose();
  assert.equal(panel.closes(), 0);
  assert.equal(panel.button('Cancel').props.disabled, true);
  panel.button('Cancel').props.onClick();
  assert.equal(panel.closes(), 0);
  assert.equal(panel.guardView().navigationDisabled, true);
  assert.equal(panel.find((node) => node.type === panel.components.DiffButton).props.navigationDisabled, true);
});

for (const [name, current] of [
  ['blocked status', guard({ status: 'blocked', reasons: ['Inventory entry no longer exists'] })],
  ['later recorded change', guard({ conflicting_proposals: ['newer-change'] })],
  ['nonempty reason', guard({ reasons: ['Saved fix differs from the executed fix'] })],
  ['transition refused', guard({ transition_allowed: false })],
  ['missing guard', null],
  ['incomplete guard', { status: 'not_checked', coverage: 'files', live_checked: false, reasons: [] }],
  ['unknown coverage', guard({ coverage: 'unknown' })],
  ['unavailable coverage', guard({ coverage: 'unavailable' })],
  ['unknown status', guard({ status: 'future_status' })],
  ['malformed reasons', guard({ reasons: 'not a list' })],
  ['missing limitations', guard({ limitations: undefined })],
]) {
  test(`${name} cannot enable confirmation`, async (t) => {
    const panel = await setup(t);
    await panel.respond(0, diff('old-change', current));
    assertBlocked(panel);
    assert.deepEqual(panel.guardView().guard, current, 'Show the actual returned evidence');
  });
}

for (const coverage of ['files', 'partial', 'unsupported']) {
  test(`explicit ${coverage} coverage permits requesting engine checks without claiming a live check`, async (t) => {
    const panel = await setup(t);
    const current = guard({ coverage, identity_bound: false });
    await panel.respond(0, diff('old-change', current));
    assert.equal(panel.button('Confirm rollback').props.disabled, false);
    assert.equal(panel.guardView().guard.live_checked, false);
    assert.equal(panel.confirmations(), 0);
  });
}

test('historical checked_files never overrides a current blocker; historical failure does not become current', async (t) => {
  const panel = await setup(t);
  await panel.respond(0, diff('old-change', guard({ status: 'blocked', reasons: ['Later change'], last_preflight: guard({ status: 'checked_files', live_checked: true }) })));
  assertBlocked(panel);
  await panel.click('Refresh checks');
  assertBlocked(panel);
  await panel.respond(1, diff('old-change', guard({ last_preflight: guard({ status: 'blocked', reasons: ['Earlier failure'] }) })));
  assert.equal(panel.button('Confirm rollback').props.disabled, false);
});

test('lookup failure and retry stay disabled until a successful response', async (t) => {
  const panel = await setup(t);
  await panel.fail();
  assertBlocked(panel);
  const error = panel.find((node) => node.type === 'ErrorBox');
  assert.equal(error.props.error, 'Static lookup failed');
  error.props.onRetry(); await panel.settle();
  assertBlocked(panel);
  await panel.respond();
  assert.equal(panel.button('Confirm rollback').props.disabled, false);
  await panel.click('Refresh checks');
  assertBlocked(panel);
  assert.ok(!panel.nodes().some((node) => node.type === panel.components.RollbackGuardView));
  await panel.fail();
  assertBlocked(panel);
});

test('a diff for another proposal cannot satisfy this confirmation', async (t) => {
  const panel = await setup(t);
  await panel.respond(0, diff('wrong-proposal'));
  assertBlocked(panel);
  assert.match(panel.find((node) => node.type === 'ErrorBox').props.error, /does not match this proposal/);
});

test('switching proposals discards delayed results, including an older failure', async (t) => {
  const panel = await setup(t);
  await panel.update({ proposal: proposal('verified', 'second') });
  assertBlocked(panel);
  await panel.respond(1, diff('second', guard({ reasons: ['Second proposal is blocked'] })));
  assertBlocked(panel);
  await panel.respond(0);
  assert.deepEqual(panel.guardView().guard.reasons, ['Second proposal is blocked']);
  await panel.click('Refresh checks');
  await panel.update({ proposal: proposal('verified', 'third') });
  await panel.respond(3);
  await panel.fail(2);
  assert.equal(panel.button('Confirm rollback').props.disabled, false);
  assert.equal(panel.guardView().guard.reasons.length, 0);
});

test('closing and reopening the same proposal requires a new lookup and ignores the old response', async (t) => {
  const panel = await setup(t);
  await panel.update({ proposal: null });
  await panel.update({ proposal: proposal() });
  assertBlocked(panel);
  await panel.respond(0);
  assertBlocked(panel);
  await panel.respond(1);
  assert.equal(panel.button('Confirm rollback').props.disabled, false);
  await panel.update({ proposal: null });
  await panel.update({ proposal: proposal() });
  assertBlocked(panel);
  assert.equal(panel.requests.length, 3, 'A completed response must also be discarded on close');
});

test('returning to a previously loaded proposal cannot reuse its earlier result while the new lookup is pending', async (t) => {
  const panel = await setup(t);
  await panel.respond(0);
  assert.equal(panel.button('Confirm rollback').props.disabled, false);
  await panel.update({ proposal: proposal('verified', 'second') });
  await panel.update({ proposal: proposal() });
  assertBlocked(panel);
  assert.equal(panel.requests.length, 3);
  await panel.respond(1);
  assertBlocked(panel);
  await panel.respond(2, diff('old-change', guard({ reasons: ['A later change now blocks this restore'] })));
  assertBlocked(panel);
});

test('Diff renders the same actual guard alongside existing outcomes and saved files', async (t) => {
  const panel = await setup(t, { component: 'ProposalDiffView' });
  const value = diff('old-change', guard({ coverage: 'partial', limitations: ['Service reload effects are not compared.'] }));
  await panel.respond(0, value);
  assert.deepEqual(panel.guardView().guard, value.rollback_guard);
  for (const title of ['Apply', 'Verify', 'Rollback']) assert.ok(panel.nodes().some((node) => node.props?.title === title));
  assert.ok(panel.nodes().some((node) => node.props?.f === value.files[0]));
  await panel.update({ proposalId: 'newer' });
  assert.ok(panel.nodes().some((node) => node.props?.what === 'Loading the diff'));
  await panel.fail();
  assert.equal(panel.find((node) => node.type === 'ErrorBox').props.error, 'Static lookup failed');
});

test('Diff button mounts the static view only when opened and conflict navigation closes both overlays', async (t) => {
  let navigations = 0;
  const panel = await setup(t, { component: 'DiffButton', props: { onNavigate: () => navigations++ } });
  assert.ok(!panel.nodes().some((node) => node.type === panel.components.ProposalDiffView));
  assert.equal(panel.requests.length, 0);
  await panel.click('Diff');
  const view = panel.find((node) => node.type === panel.components.ProposalDiffView);
  assert.equal(view.props.proposalId, 'old-change');
  view.props.onNavigate(); await panel.settle();
  assert.equal(navigations, 1);
  assert.ok(!panel.nodes().some((node) => node.type === panel.components.ProposalDiffView));
});

test('conflict links use encoded history destinations and respect busy navigation', async (t) => {
  let navigations = 0, prevented = 0;
  const panel = await setup(t, { component: 'RollbackGuardView', props: {
    guard: guard({ conflicting_proposals: ['later/change?&<x>'] }), onNavigate: () => navigations++,
  } });
  const link = () => panel.find((node) => node.type === 'Anchor');
  assert.equal(link().props.to, '/?proposal=later%2Fchange%3F%26%3Cx%3E');
  link().props.onClick({ preventDefault: () => prevented++ });
  assert.equal(navigations, 1);
  await panel.update({ navigationDisabled: true });
  assert.equal(link().props['aria-disabled'], true);
  link().props.onClick({ preventDefault: () => prevented++ });
  assert.equal(prevented, 1);
  assert.equal(navigations, 1);
});
