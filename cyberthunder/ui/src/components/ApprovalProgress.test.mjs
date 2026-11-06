import assert from 'node:assert/strict';
import test from 'node:test';
import { createRequire } from 'node:module';
import { createElement as h } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createModuleLoader } from '../lib/moduleTestSupport.mjs';
import { protectedProposal, session, vote } from '../lib/approvalTestSupport.mjs';

const require = createRequire(import.meta.url);
const { MantineProvider } = require('@mantine/core');
const plain = html => html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ');
function render(p, identity = session('reviewer-2')) {
  const load = createModuleLoader();
  load(new URL('../api/identity.ts', import.meta.url)).setSessionIdentity(identity);
  const { ApprovalProgress } = load(new URL('./ApprovalProgress.tsx', import.meta.url), {
    '../lib/format': { fmtZonedTime: at => at, label: text => text },
    './common': { Collapsible: props => h('section', { 'aria-label': props.title }, props.children) },
  });
  return renderToStaticMarkup(h(MantineProvider, {}, h(ApprovalProgress, { proposal: p })));
}

test('partial view states counts, remaining approvals and the actual proposed state', () => {
  const html = render(protectedProposal({ approvals: [vote()] }));
  assert.match(plain(html), /1 of 2 distinct human approvals recorded/);
  assert.match(plain(html), /1 remaining\. Server state: proposed/);
  assert.doesNotMatch(plain(html), /Server state: approved/);
  for (const value of ['Proposed by Reviewer proposer', 'Approval recorded by Reviewer reviewer-1',
    'Verified at proposal creation (OIDC)', 'Verified at decision (OIDC)', 'https://identity.example',
    'Subject: reviewer-1', 'Audit actor: human:reviewer-1', 'shared-receipt', 'payload-digest', 'assessment-digest']) {
    assert.ok(plain(html).includes(value), value);
  }
});

test('proposer and duplicate denial explanations are rendered with progress', () => {
  const p = protectedProposal({ approvals: [vote()] });
  assert.match(plain(render(p, session('proposer'))), /You proposed this change\. Another person must approve it/);
  assert.match(plain(render(p, session())), /Your approval is already recorded\. A different person/);
  assert.match(plain(render({ ...p, state: 'approved', approvals: [vote(), vote('reviewer-2')] })), /2 of 2.*0 remaining\. Server state: approved/);
});

test('provenance allowlists public fields and labels local decisions explicitly', () => {
  const secrets = { session_id: 'PRIVATE-SESSION', access_token: 'PRIVATE-TOKEN', csrf_token: 'PRIVATE-CSRF' };
  const v = vote();
  Object.assign(v.principal, secrets);
  const p = protectedProposal({ approvals: [v] });
  Object.assign(p.proposed_principal, secrets);
  const html = render(p, { ...session(), ...secrets });
  for (const secret of Object.values(secrets)) assert.ok(!html.includes(secret));
  p.approval_requirements.mode = 'unverified_dev';
  v.principal.verified = false; v.principal.via = 'dev';
  assert.match(plain(render(p, null)), /1 of 2 distinct local approvals recorded/);
  assert.match(plain(render(p, null)), /Typed names do not authenticate people/);
});
