// Companion to rehearse_browser.py. All mutations target its new simulated state.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { pathToFileURL } from 'node:url';

const [output, moduleName, executablePath, evidence = output] = process.argv.slice(2);
const fixture = JSON.parse(readFileSync(join(output, 'fixture.json'), 'utf8'));
assert.equal(fixture.simulated_only, true);
const base = `http://127.0.0.1:${fixture.port}`;
const report = { ...fixture, started_at: new Date().toISOString(), steps: [], errors: [],
  phase: 'launch', blocked_requests: 0, screenshots: [] };
let browser, page;

async function get(path) {
  const response = await page.request.get(`${base}/api/v1/${path}`, { maxRedirects: 0 });
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
// Compare the observation independently of live review, confidence and remediation projections.
const observation = ({ review, confidence, fix, explanation, remediated, rollback, needs_rescan,
  proposal, status, scanner_status, ...raw }) => ({ ...raw, status: scanner_status });
const digest = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const proposalRecord = ({ finding, policy, ...record }) => record;
async function proposalRecords() {
  return (await get('proposals')).proposals.map(proposalRecord).sort((a, b) => a.id.localeCompare(b.id));
}
async function totals() {
  const all = await get('findings?limit=5000');
  const open = await get('findings?status=open&limit=5000');
  return { total: all.total, unfiltered_total: all.unfiltered_total, open: open.total,
    status: all.facets.status, severity: all.facets.severity };
}
async function screenshot(name) {
  await page.screenshot({ path: join(evidence, name + '.png'), fullPage: false });
  report.screenshots.push(name + '.png');
}
async function closeDrawer() {
  await page.keyboard.press('Escape');
  await page.getByRole('dialog', { name: 'Finding detail', exact: true }).waitFor({ state: 'hidden' });
}
async function uiRiskSubmission(button, method, path) {
  const [response] = await Promise.all([
    page.waitForResponse(r => r.url() === `${base}/api/v1/${path}` && r.request().method() === method),
    button.click(),
  ]);
  assert.equal(response.status(), 200, `UI ${method} ${path}: ${await response.text()}`);
  const body = response.request().postDataJSON();
  report.steps.push({ step: 'ui_risk_submission', method, path, status: response.status(),
    reason: body.reason, supporting_evidence: body.supporting_evidence, expires_at: body.expires_at });
  return response.json();
}
try {
  const { chromium } = await import(isAbsolute(moduleName) ? pathToFileURL(moduleName).href : moduleName);
  browser = await chromium.launch({ ...(executablePath ? { executablePath } : {}), headless: true });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 },
    timezoneId: 'UTC', serviceWorkers: 'block' });
  await context.route('**/*', route => {
    if (new URL(route.request().url()).origin === base) return route.continue();
    report.blocked_requests++;
    return route.abort();
  });
  await context.routeWebSocket('**/*', route => { report.blocked_requests++; route.close(); });
  page = await context.newPage();
  page.setDefaultTimeout(20000);
  page.on('pageerror', error => report.errors.push(error.message));
  report.browser_version = browser.version();
  report.phase = 'approval';
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

  report.phase = 'risk_acceptance_ui';
  const originalFinding = await get('findings/' + fixture.finding);
  const originalObservation = observation(originalFinding);
  const originalHistorical = observation(await get(`findings/${fixture.finding}?scan_id=${fixture.scan}`));
  const originalTotals = await totals();
  const originalProposals = await proposalRecords();
  assert.equal(originalFinding.status, 'open');
  assert.equal(originalFinding.scanner_status, 'open');
  assert.equal(originalFinding.review.remediation_held, false);
  assert.ok(originalProposals.some(p => p.state === 'proposed'), 'Retain unapproved control proposals');
  const observationHash = digest(originalObservation);
  async function unchangedRiskEvidence() {
    const finding = await get('findings/' + fixture.finding);
    assert.deepEqual(observation(finding), originalObservation, 'Raw current observation changed');
    assert.deepEqual(observation(await get(`findings/${fixture.finding}?scan_id=${fixture.scan}`)),
      originalHistorical, 'Historical scanner observation changed');
    assert.equal(finding.status, 'open');
    assert.equal(finding.remediated, originalFinding.remediated);
    assert.deepEqual(await totals(), originalTotals, 'Risk decision changed scanner totals or severity facets');
    assert.deepEqual(await proposalRecords(), originalProposals, 'Risk decision changed proposal/approval records');
    return finding;
  }
  async function findingRow() {
    await page.getByRole('link', { name: 'Findings', exact: true }).click();
    await page.getByText(`${originalTotals.open.toLocaleString()} matching / ${originalTotals.total.toLocaleString()} total results`,
      { exact: true }).waitFor();
    const row = page.getByRole('row', {
      name: `Open finding ${originalFinding.rule_version || originalFinding.rule_id}: ${originalFinding.title} on ${originalFinding.host}`,
      exact: true,
    });
    await row.getByText('Failed / open', { exact: true }).waitFor();
    return row;
  }
  const row = await findingRow();
  const severityLabel = await row.locator('td').first().innerText();
  const openFinding = () => row.getByRole('button', { name: `Open finding ${originalFinding.rule_version || originalFinding.rule_id}`, exact: true }).click();
  await openFinding();
  const drawer = page.getByRole('dialog', { name: 'Finding detail', exact: true });
  await drawer.getByRole('button', { name: /^Review and history/ }).click();
  await drawer.getByText('Local / unverified reviewer', { exact: true }).waitFor();
  await drawer.getByRole('textbox', { name: 'Review decision', exact: true }).click();
  await page.getByRole('option', { name: 'Risk accepted', exact: true }).click();
  const acceptReason = 'Temporary simulated maintenance constraint; retain the open scanner risk.';
  const acceptEvidence = 'Isolated rehearsal maintenance record; no official risk authorization.';
  const expiryLocal = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString().slice(0, 16);
  await drawer.getByRole('textbox', { name: 'Reason', exact: true }).fill(acceptReason);
  await drawer.getByRole('textbox', { name: 'Supporting evidence', exact: true }).fill(acceptEvidence);
  // The native date input's label includes the form library's required marker.
  await drawer.getByLabel(/^Expiry \(required\)/).fill(expiryLocal);
  const acceptance = await uiRiskSubmission(drawer.getByRole('button', { name: 'Accept risk', exact: true }),
    'PUT', `findings/${fixture.finding}/risk-acceptance`);
  assert.equal(acceptance.current.reason, acceptReason);
  assert.equal(acceptance.current.supporting_evidence, acceptEvidence);
  assert.equal(Date.parse(acceptance.current.expires_at), Date.parse(expiryLocal + ':00Z'));
  assert.equal(acceptance.current.identity_verified, false);
  await drawer.getByText('Risk accepted — remediation held', { exact: true }).waitFor();
  await drawer.getByText('The scanner failure and severity remain.', { exact: false }).waitFor();
  await drawer.getByText('Expires: ' + expiryLocal.replace('T', ' ') + ':00', { exact: true }).waitFor();
  assert.ok((await drawer.innerText()).includes(acceptReason));
  assert.ok((await drawer.innerText()).includes(acceptEvidence));
  assert.ok((await drawer.innerText()).includes(originalFinding.evidence));
  assert.equal(await drawer.getByRole('button', { name: 'Propose fix', exact: true }).isDisabled(), true);
  await drawer.getByText('Risk accepted — remediation held', { exact: true }).scrollIntoViewIfNeeded();
  await screenshot('risk-accepted-drawer');
  await closeDrawer();
  await row.getByText('Remediation held', { exact: true }).waitFor();
  assert.equal(await row.locator('td').first().innerText(), severityLabel);
  await row.getByText('Failed / open', { exact: true }).waitFor();
  await page.getByText(`${originalTotals.open.toLocaleString()} matching / ${originalTotals.total.toLocaleString()} total results`,
    { exact: true }).waitFor();
  const heldFinding = await unchangedRiskEvidence();
  assert.equal(heldFinding.review.remediation_held, true);
  assert.equal(heldFinding.review.risk_acceptance_status, 'active');
  assert.equal(heldFinding.review.suppressed, false);
  report.steps.push({ step: 'risk_hold_evidence', observation_sha256: observationHash,
    historical_observation_sha256: digest(originalHistorical), severity: heldFinding.severity,
    totals: originalTotals, proposal_records_unchanged: true, identity_verified: false });

  report.phase = 'risk_hold_apply_guard';
  await page.goto(`${base}/#/?proposal=${fixture.proposal}`);
  await card.getByText('Remediation held by risk acceptance', { exact: true }).waitFor();
  assert.equal(await card.getByRole('button', { name: 'Apply', exact: true }).isDisabled(), true);
  await card.getByText('Remediation held by risk acceptance', { exact: true }).scrollIntoViewIfNeeded();
  await screenshot('risk-held-apply');
  const riskRefused = await page.request.post(`${base}/api/v1/proposals/${fixture.proposal}/apply`,
    { headers: { 'X-Actor': 'Browser rehearsal' }, data: {}, maxRedirects: 0 });
  assert.equal(riskRefused.status(), 409);
  assert.match((await riskRefused.json()).detail, /Risk acceptance holds remediation/);
  await unchangedRiskEvidence();
  report.steps.push({ step: 'risk_apply_guard', ui_apply_disabled: true, refusal: riskRefused.status(), state: 'approved' });

  report.phase = 'risk_revocation_ui';
  await findingRow();
  await openFinding();
  await drawer.getByRole('button', { name: /^Review and history/ }).click();
  await drawer.getByRole('button', { name: 'Prepare risk revocation', exact: true }).click();
  const revokeReason = 'Simulated maintenance window available; resume the separately approved change.';
  await drawer.getByRole('textbox', { name: 'Reason', exact: true }).fill(revokeReason);
  const revocation = await uiRiskSubmission(drawer.getByRole('button', { name: 'Revoke risk acceptance', exact: true }),
    'POST', `findings/${fixture.finding}/risk-acceptance/revoke`);
  assert.equal(revocation.risk_acceptance_status, 'revoked');
  assert.equal(revocation.remediation_held, false);
  assert.equal(revocation.disposition, 'unreviewed');
  assert.equal(revocation.current.reason, revokeReason);
  assert.equal(revocation.current.identity_verified, false);
  assert.deepEqual(revocation.history, [...acceptance.history, revocation.current]);
  await drawer.getByText('Risk acceptance revoked', { exact: true }).first().waitFor();
  await drawer.getByRole('paragraph').filter({ hasText: revokeReason }).waitFor();
  await drawer.getByRole('paragraph').filter({ hasText: acceptReason }).waitFor();
  await drawer.getByRole('button', { name: 'Revoke risk acceptance', exact: true }).waitFor({ state: 'hidden' });
  assert.equal(await drawer.getByRole('textbox', { name: 'Reason', exact: true }).inputValue(), '');
  await drawer.getByRole('button', { name: 'Save review', exact: true }).waitFor();
  await drawer.getByText('Review history', { exact: true }).scrollIntoViewIfNeeded();
  await screenshot('risk-revoked-history');
  await closeDrawer();
  await row.getByRole('button', { name: 'Unreviewed: open human review and history', exact: true }).waitFor();
  await row.getByText('Failed / open', { exact: true }).waitFor();
  assert.equal(await row.locator('td').first().innerText(), severityLabel);
  await unchangedRiskEvidence();
  await page.goto(`${base}/#/?proposal=${fixture.proposal}`);
  await card.getByRole('button', { name: 'Apply', exact: true }).waitFor();
  assert.equal(await card.getByRole('button', { name: 'Apply', exact: true }).isEnabled(), true);
  assert.equal(await card.getByText('Remediation held by risk acceptance', { exact: true }).count(), 0);
  report.steps.push({ step: 'risk_revocation', status: 'revoked', disposition: 'unreviewed',
    completed_form_cleared: true,
    ui_apply_enabled: true, proposal_records_unchanged: true, observation_sha256: observationHash,
    unapproved_control_proposals: originalProposals.filter(p => p.state === 'proposed').length,
    history_dispositions: revocation.history.map(event => event.disposition) });

  report.phase = 'kill_guard';
  await page.getByRole('button', { name: 'Engage kill switch', exact: true }).click();
  await dialog.getByRole('textbox', { name: 'Reason', exact: true }).fill('Rehearsal stop before any change');
  await dialog.getByRole('button', { name: 'Engage kill switch', exact: true }).click();
  await page.getByRole('button', { name: 'Release kill switch', exact: true }).waitFor();
  assert.equal(await card.getByRole('button', { name: 'Apply', exact: true }).isDisabled(), true);
  const refused = await page.request.post(`${base}/api/v1/proposals/${fixture.proposal}/apply`,
    { headers: { 'X-Actor': 'Browser rehearsal' }, data: {}, maxRedirects: 0 });
  assert.equal(refused.status(), 423);
  assert.equal((await get('proposals/' + fixture.proposal)).state, 'approved');
  report.steps.push({ step: 'kill_guard', refusal: refused.status(), state: 'approved' });
  await page.getByRole('button', { name: 'Release kill switch', exact: true }).click();
  await dialog.getByRole('textbox', { name: 'Reason', exact: true }).fill('Resume this simulated rehearsal');
  await dialog.getByRole('button', { name: 'Release', exact: true }).click();
  await dialog.waitFor({ state: 'hidden' });
  await page.locator('button[aria-label="Engage kill switch"]').waitFor();

  report.phase = 'apply_and_recovery';
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
  report.phase = 'reload_and_audit';
  await page.reload();
  await card.getByText('This change was rolled back.', { exact: false }).waitFor();
  const audit = await get('audit/verify');
  assert.equal(audit.ok, true);
  assert.deepEqual(report.errors, []);
  assert.equal(report.blocked_requests, 0, 'Unexpected network request blocked');
  const savedReview = await get(`findings/${fixture.finding}/review`);
  assert.deepEqual(savedReview.history, revocation.history, 'Risk decision history changed during remediation');
  assert.deepEqual(observation(await get(`findings/${fixture.finding}?scan_id=${fixture.scan}`)), originalHistorical);
  report.steps.push({ step: 'reload_and_audit', audit });
  await card.getByText('This change was rolled back.', { exact: false }).scrollIntoViewIfNeeded();
  await screenshot('restored-decision');
  report.phase = 'complete';
  report.passed = true;
} catch (error) {
  report.passed = false;
  report.failure = String(error);
  if (page) {
    try { await screenshot('failure'); } catch (captureError) { report.capture_failure = String(captureError); }
  }
  console.error(String(error));
  process.exitCode = 1;
} finally {
  report.finished_at = new Date().toISOString();
  writeFileSync(join(evidence, 'result.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify({ backend: fixture.backend, scenario: fixture.scenario, passed: report.passed }));
  if (browser) await browser.close();
}
