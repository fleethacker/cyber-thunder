import assert from 'node:assert/strict';
import test from 'node:test';
import { createRequire } from 'node:module';
import { createElement as h } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { evaluate } from '../lib/moduleTestSupport.mjs';

const require = createRequire(import.meta.url);
const { MantineProvider } = require('@mantine/core');
const { FileProvenance } = evaluate(new URL('./LibraryTables.tsx', import.meta.url), {
  '../lib/format': { fmtZonedTime: (at) => at || 'Not recorded' },
});
const render = (authenticity) => renderToStaticMarkup(h(MantineProvider, {}, h(FileProvenance, {
  file: { source: 'imported', fetched_by: '<script>actor</script>', authenticity },
})));

test('recorded signer, scope and human exception are escaped text, never executable markup', () => {
  const attack = '<img src=x onerror="alert(1)">';
  const html = render({ status: 'human_override', signer: attack, scope: attack,
    key_sha256: attack, override_by: attack, override_reason: attack });
  assert.ok(!html.includes('<img'));
  assert.ok(!html.includes('<script>'));
  assert.ok(html.includes('&lt;img src=x onerror=&quot;alert(1)&quot;&gt;'));
  assert.ok(html.includes('&lt;script&gt;actor&lt;/script&gt;'));
  assert.match(html, /Accepted by a human exception; authenticity not established/);
  assert.match(html, /Recorded signer/);
  assert.match(html, /Recorded key SHA-256/);
});

test('provenance distinguishes imported operator evidence from transport, legacy and publisher assurance', () => {
  assert.match(render({ status: 'operator_attested', operator_attested: true }), /at import; no DISA signature claimed/);
  assert.match(render({ status: 'trusted_https_source' }), /verified HTTPS; no publisher signature/);
  for (const evidence of [undefined, { status: 'unsigned_dev' }, { status: 'operator_attested', operator_attested: false },
    { status: 'unrecognized', disa_signature: true, signer: 'untrusted label' }]) {
    assert.match(render(evidence), /authenticity not established/);
  }
});

test('library activation is shown separately from authenticity and incomplete recording', () => {
  const fileHtml = (file) => renderToStaticMarkup(h(MantineProvider, {}, h(FileProvenance, {
    file: { source: 'imported', ...file },
  })));
  const historical = fileHtml({ active: false, authenticity: { status: 'operator_attested', operator_attested: true } });
  assert.match(historical, /Stored reference/);
  assert.doesNotMatch(historical, /Active in library/);
  const current = fileHtml({ active: true, commit_status: 'committed_with_bookkeeping_pending',
    authenticity: { status: 'human_override' } });
  assert.match(current, /Active in library/);
  assert.match(current, /authenticity not established/);
  assert.match(current, /Final recording pending/);
  for (const active of [undefined, null, 1, 'true']) {
    const unknown = fileHtml({ active });
    assert.match(unknown, /Activation not recorded/);
    assert.doesNotMatch(unknown, /Active in library/);
  }
});
