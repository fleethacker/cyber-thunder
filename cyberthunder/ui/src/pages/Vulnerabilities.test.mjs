import assert from 'node:assert/strict';
import test from 'node:test';
import { ApiError, errorText, evaluate, fixture, jobFixture, mount, ui } from '../components/vulnerabilityTestSupport.mjs';

async function setup(t, overrides = {}, faults = {}) {
  let current = { ...fixture(), ...overrides }, history = current.active_job ? [current.active_job] : [];
  const context = { status: { kill: { engaged: false }, link: { connected: true } }, statusError: null, actor: 'IT1 Reviewer' };
  const calls = [], timers = new Map();
  let timerID = 0, failRead = !!faults.status, failJobs = false, failImport = false;
  const previousWindow = globalThis.window;
  globalThis.window = { setInterval(fn, delay) { const id = ++timerID; timers.set(id, { fn, delay }); return id; }, clearInterval(id) { timers.delete(id); }, setTimeout: (fn) => { fn(); } };
  const api = {
    async vulnerabilities() { calls.push(['status']); if (failRead) throw new Error('Fixture status unavailable'); return structuredClone(current); },
    async vulnerabilityJobs() { calls.push(['jobs']); if (failJobs) throw new Error('Fixture progress unavailable'); return { jobs: structuredClone(history) }; },
    async updateVulnerabilityDatabases(includeJava) { calls.push(['update', includeJava]); const job = jobFixture(); current.active_job = job; history = [job]; return structuredClone(job); },
    async importVulnerabilityBundle(file) { calls.push(['import', file]); if (failImport) throw new ApiError(400, 'Bundle hash mismatch'); current = { ...current, provenance: 'offline_import' }; return structuredClone(current); },
    async exportVulnerabilityBundle() { calls.push(['export']); return new Blob(['fixture zip']); },
    async saveVulnerabilitySettings(input) { calls.push(['settings', input]); current.settings = { ...input, revision: input.expected_revision + 1 }; return structuredClone(current.settings); },
  };
  const { actorProblem } = evaluate(new URL('../components/ActorChip.tsx', import.meta.url), { '@mantine/core': ui, '../state/AppState': {} });
  const panel = mount((hooks) => {
    const { useInterval } = evaluate(new URL('../lib/hooks.ts', import.meta.url), { react: hooks, '../api/client': { errorText } });
    return evaluate(new URL('./Vulnerabilities.tsx', import.meta.url), {
      react: hooks, '@mantine/core': ui, '../api/client': { api, ApiError, errorText }, '../lib/hooks': { useInterval },
      '../components/ActorChip': { actorProblem }, '../components/common': ui,
      '../state/AppState': { useAppState: () => context },
      '../components/VulnerabilitySchedule': ui,
      '../components/VulnerabilityStatus': { ...ui, VulnerabilityStatus: 'VulnerabilityStatus', VulnerabilityJobs: 'VulnerabilityJobs', vulnerabilityJobActive: (job) => ['pending', 'running'].includes(job.state) },
    }).default;
  });
  t.after(() => { panel.unmount(); globalThis.window = previousWindow; });
  await panel.settle();
  return { ...panel, context, calls, timers,
    async tick() { for (const timer of [...timers.values()]) timer.fn(); await panel.settle(); },
    status() { return panel.find((node) => node.type === 'VulnerabilityStatus').props.data; },
    jobs() { return panel.find((node) => node.type === 'VulnerabilityJobs').props.jobs; },
    schedule() { return panel.find((node) => node.type === 'VulnerabilitySchedule').props; },
    update(value, jobs = history) { current = { ...current, ...value }; history = jobs; },
    failRead(value = true) { failRead = value; }, failJobs(value = true) { failJobs = value; }, failImport(value = true) { failImport = value; },
  };
}

const writes = (panel) => panel.calls.filter(([kind]) => !['status', 'jobs'].includes(kind));

test('mount, refresh and passive polling only read local status; saved opt-in remains passive in the browser', async (t) => {
  const panel = await setup(t, { settings: { ...fixture().settings, auto_update: true } });
  assert.equal(panel.schedule().settings.auto_update, true);
  await panel.click('Refresh local status');
  await panel.tick();
  assert.deepEqual(writes(panel), []);
  assert.equal(panel.calls.filter(([kind]) => kind === 'status').length, 3);
});

test('explicit update follows the Java selection, polls while active, then reports completion', async (t) => {
  const panel = await setup(t);
  await panel.change('Include Java database in this update', false);
  await panel.click('Update databases');
  assert.deepEqual(writes(panel), [['update', false]]);
  assert.equal(panel.jobs()[0].state, 'pending');
  assert.equal([...panel.timers.values()][0].delay, 1500);
  assert.equal(panel.button('Update databases').props.disabled, true);
  const completed = { ...jobFixture('completed'), finished_at: '2026-11-05T15:01:00Z' };
  panel.update({ active_job: null }, [completed]);
  await panel.tick();
  assert.equal(panel.jobs()[0].state, 'completed');
  assert.equal([...panel.timers.values()][0].delay, 10000);
  assert.equal(panel.button('Update databases').props.disabled, false);
  panel.unmount();
  assert.equal(panel.timers.size, 0);
});

test('progress errors retain active jobs and block writes until a successful poll', async (t) => {
  const panel = await setup(t, { active_job: jobFixture('running') });
  panel.failJobs();
  panel.failRead();
  await panel.tick();
  assert.equal(panel.jobs()[0].state, 'running');
  assert.ok(panel.nodes().some((node) => node.props?.error?.includes('Fixture progress unavailable')));
  assert.ok(panel.nodes().some((node) => node.props?.error?.includes('Showing the last loaded status')));
  assert.equal(panel.schedule().disabled, true);
  assert.equal([...panel.timers.values()][0].delay, 1500);
  panel.failJobs(false); panel.failRead(false);
  const failed = { ...jobFixture('failed'), error: 'Fixture download failed' };
  panel.update({ active_job: null, last_error: failed.error }, [failed]);
  await panel.tick();
  assert.equal(panel.jobs()[0].error, 'Fixture download failed');
  assert.equal(panel.status().last_error, 'Fixture download failed');
  assert.equal(panel.schedule().disabled, false);
});

test('active jobs keep polling even when the initial database status request fails', async (t) => {
  const panel = await setup(t, { active_job: jobFixture('running') }, { status: true });
  assert.equal(panel.jobs()[0].state, 'running');
  assert.equal([...panel.timers.values()][0].delay, 1500);
  assert.ok(panel.nodes().some((node) => node.props?.error?.includes('Fixture status unavailable')));
  panel.failRead(false);
  await panel.tick();
  assert.equal(panel.status().state, 'ready');
  assert.deepEqual(writes(panel), []);
});

test('rapid repeated update clicks create only one job', async (t) => {
  const panel = await setup(t);
  const click = panel.button('Update databases').props.onClick;
  click(); click();
  await panel.settle();
  assert.deepEqual(writes(panel), [['update', true]]);
});

test('actor, kill and unknown node status gates block all writes, including invoked handlers', async (t) => {
  const panel = await setup(t);
  await panel.change('Offline database ZIP', new File(['zip'], 'db.zip'));
  const baseline = structuredClone(panel.context);
  for (const change of [{ actor: '' }, { actor: 'system' }, { actor: 'policy:schedule' }, { status: { ...baseline.status, kill: { engaged: true } } }, { status: null }, { statusError: 'Node unreachable' }]) {
    Object.assign(panel.context, structuredClone(baseline), change);
    await panel.rerender();
    for (const name of ['Update databases', 'Upload offline ZIP', 'Export ZIP']) {
      assert.equal(panel.button(name).props.disabled, true);
      await panel.click(name, true);
    }
    const settings = panel.schedule();
    assert.equal(settings.disabled, true);
    await assert.rejects(settings.onSave({ expected_revision: 1, auto_update: true, interval_hours: 12, include_java: false }));
  }
  assert.deepEqual(writes(panel), []);
});

test('offline ZIP requires an explicit upload and preserves the selected file after refusal', async (t) => {
  const panel = await setup(t);
  panel.context.status.link.connected = false;
  await panel.rerender();
  assert.equal(panel.button('Update databases').props.disabled, true);
  await panel.change('Offline database ZIP', new File(['x'], 'db.txt'));
  assert.equal(panel.button('Upload offline ZIP').props.disabled, true);
  await panel.click('Upload offline ZIP', true);
  const file = new File(['fixture zip'], 'offline.ZIP');
  await panel.change('Offline database ZIP', file);
  assert.deepEqual(writes(panel), []);
  panel.failImport();
  await panel.click('Upload offline ZIP');
  assert.equal(panel.control('Offline database ZIP').props.value, file);
  assert.ok(panel.nodes().some((node) => node.props?.error === 'Bundle hash mismatch'));
  panel.failImport(false);
  await panel.click('Upload offline ZIP');
  assert.equal(panel.status().provenance, 'offline_import');
  assert.equal(panel.control('Offline database ZIP').props.value, null);
  assert.deepEqual(writes(panel), [['import', file], ['import', file]]);
});

test('restricted or unknown links do not claim offline or permit online update handlers', async (t) => {
  const panel = await setup(t);
  for (const change of [
    { global_details: false, link: null },
    { global_details: true, link: null },
    { global_details: false, link: { connected: true } },
  ]) {
    Object.assign(panel.context.status, change);
    await panel.rerender();
    assert.equal(panel.button('Update databases').props.disabled, true);
    await panel.click('Update databases', true);
    const textNodes = panel.nodes().filter((node) => node.type === 'Text' && typeof node.props.children === 'string');
    assert.ok(textNodes.some((node) => node.props.children.includes('Online update availability cannot be determined')));
    assert.ok(!textNodes.some((node) => node.props.children.includes('The node is offline')));
    assert.equal(panel.button('Refresh local status').props.disabled, false);
  }
  assert.deepEqual(writes(panel), []);
});

test('export creates a browser ZIP download only after an explicit click', async (t) => {
  const previousDocument = globalThis.document;
  const previousCreate = URL.createObjectURL, previousRevoke = URL.revokeObjectURL;
  const events = [];
  const link = { click() { events.push('click'); }, remove() { events.push('remove'); } };
  globalThis.document = { createElement: () => link, body: { appendChild: () => events.push('append') } };
  URL.createObjectURL = (blob) => { assert.equal(blob.size, 11); return 'blob:fixture'; };
  URL.revokeObjectURL = (url) => events.push(url);
  t.after(() => { globalThis.document = previousDocument; URL.createObjectURL = previousCreate; URL.revokeObjectURL = previousRevoke; });
  const panel = await setup(t);
  assert.deepEqual(events, []);
  await panel.click('Export ZIP');
  assert.deepEqual(writes(panel), [['export']]);
  assert.equal(link.download, 'cyber-thunder-vulnerability-databases.zip');
  assert.equal(link.href, 'blob:fixture');
  assert.deepEqual(events, ['append', 'click', 'remove', 'blob:fixture']);
});

test('missing main database disables export and unsupported scanner disables online update', async (t) => {
  const panel = await setup(t, { state: 'missing', generation: null, databases: [], engine: { available: true, supported: false, version: '0.70.0', error: 'Unsupported scanner' } });
  assert.equal(panel.button('Export ZIP').props.disabled, true);
  assert.equal(panel.button('Update databases').props.disabled, true);
  await panel.click('Export ZIP', true);
  await panel.click('Update databases', true);
  assert.deepEqual(writes(panel), []);
});
