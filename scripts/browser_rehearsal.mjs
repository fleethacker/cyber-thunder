// Companion to rehearse_browser.py. All mutations target its new simulated state.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { pathToFileURL } from 'node:url';

const [output, moduleName, executablePath] = process.argv.slice(2);
const { chromium } = await import(isAbsolute(moduleName) ? pathToFileURL(moduleName).href : moduleName);
const fixture = JSON.parse(readFileSync(join(output, 'fixture.json'), 'utf8'));
assert.equal(fixture.simulated_only, true);
const base = `http://127.0.0.1:${fixture.port}`;
const report = { ...fixture, started_at: new Date().toISOString(), steps: [], errors: [] };
const browser = await chromium.launch({ ...(executablePath ? { executablePath } : {}), headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
page.setDefaultTimeout(20000);
page.on('pageerror', error => report.errors.push(error.message));
await page.route('**/*', route => new URL(route.request().url()).origin === base ? route.continue() : route.abort());

async function get(path) {
  const response = await page.request.get(`${base}/api/v1/${path}`);
  assert.equal(response.status(), 200, `${path}: ${await response.text()}`);
  return response.json();
}
async function waitState(state) {
  for (let i = 0; i < 120; i++) {
    const proposal = await get('proposals/' + fixture.proposal);
    if (proposal.state === state) return proposal;
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  throw new Error('Proposal did not reach ' + state);
}
const findingSummary = finding => ({ status: finding.status, scanner_status: finding.scanner_status,
  remediated: finding.remediated, needs_rescan: finding.needs_rescan, rollback: finding.rollback });
try {
  await page.goto(`${base}/#/?proposal=${fixture.proposal}`);
  await page.getByRole('textbox', { name: 'Acting as', exact: true }).fill('Browser rehearsal');
  await page.getByRole('button', { name: 'Save', exact: true }).click();
  const card = page.locator('#proposal-' + fixture.proposal);
  await card.getByRole('button', { name: 'Approve', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByRole('checkbox', { name: 'Use stored declarations only; do not contact the target', exact: true }).check();
  await dialog.getByRole('button', { name: 'Collect and assess dependencies', exact: true }).click();
  await dialog.getByRole('checkbox', { name: 'I reviewed the risks, unknowns, checks and rollback limitations', exact: true }).check();
  await dialog.getByRole('textbox', { name: 'Review note and treatment of unresolved dependencies', exact: false })
    .fill('Isolated simulated target: reviewed declared risks, unresolved dependencies and restore limits.');
  await dialog.getByRole('button', { name: 'Approve reviewed change', exact: true }).click();
  const approved = await waitState('approved');
  assert.equal(approved.decided_by, 'Browser rehearsal');
  assert.equal(approved.assessment.status, 'reviewed');
  report.steps.push({ step: 'approval', state: approved.state, assessment: approved.assessment.status });

  await page.getByRole('button', { name: 'Engage kill switch', exact: true }).click();
  await dialog.getByRole('textbox', { name: 'Reason', exact: true }).fill('Rehearsal stop before any change');
  await dialog.getByRole('button', { name: 'Engage kill switch', exact: true }).click();
  await page.getByRole('button', { name: 'Release kill switch', exact: true }).waitFor();
  assert.equal(await card.getByRole('button', { name: 'Apply', exact: true }).isDisabled(), true);
  const refused = await page.request.post(`${base}/api/v1/proposals/${fixture.proposal}/apply`,
    { headers: { 'X-Actor': 'Browser rehearsal' }, data: {} });
  assert.equal(refused.status(), 423);
  assert.equal((await get('proposals/' + fixture.proposal)).state, 'approved');
  report.steps.push({ step: 'kill_guard', refusal: refused.status(), state: 'approved' });
  await page.getByRole('button', { name: 'Release kill switch', exact: true }).click();
  await dialog.getByRole('textbox', { name: 'Reason', exact: true }).fill('Resume this simulated rehearsal');
  await dialog.getByRole('button', { name: 'Release', exact: true }).click();
  await dialog.waitFor({ state: 'hidden' });
  await page.locator('button[aria-label="Engage kill switch"]').waitFor();

  await card.getByRole('button', { name: 'Apply', exact: true }).click();
  if (fixture.scenario === 'normal') {
    const verified = await waitState('verified');
    assert.ok(verified.before_state_ref);
    const finding = await get('findings/' + fixture.finding);
    assert.equal(finding.status, 'not_a_finding');
    assert.equal(finding.scanner_status, 'open');
    report.steps.push({ step: 'apply_and_verify', state: verified.state, finding: findingSummary(finding) });
    await card.getByRole('button', { name: 'Rollback', exact: true }).click();
    await dialog.getByRole('button', { name: 'Confirm rollback', exact: true }).click();
  }
  const restored = await waitState('rolled_back');
  const finding = await get('findings/' + fixture.finding);
  assert.equal(finding.status, 'open');
  assert.equal(finding.needs_rescan, true);
  if (fixture.scenario === 'verification_failure') {
    assert.ok(restored.history.some(entry => entry.state === 'failed'));
    assert.ok(!restored.history.some(entry => entry.state === 'verified'));
  }
  report.steps.push({ step: fixture.scenario === 'normal' ? 'manual_rollback' : 'verification_failure_recovery',
    state: restored.state, finding: findingSummary(finding) });
  await page.reload();
  await card.getByText('This change was rolled back.', { exact: false }).waitFor();
  const audit = await get('audit/verify');
  assert.equal(audit.ok, true);
  assert.deepEqual(report.errors, []);
  report.steps.push({ step: 'reload_and_audit', audit });
  report.passed = true;
} catch (error) {
  report.passed = false;
  report.failure = String(error);
  await page.screenshot({ path: join(output, 'failure.png'), fullPage: false });
  console.error(String(error));
  process.exitCode = 1;
} finally {
  report.finished_at = new Date().toISOString();
  writeFileSync(join(output, 'result.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify({ backend: fixture.backend, scenario: fixture.scenario, passed: report.passed }));
  await browser.close();
}
