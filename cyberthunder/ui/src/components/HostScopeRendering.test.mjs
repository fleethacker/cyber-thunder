import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { MantineProvider } from '@mantine/core';
import ts from 'typescript';

const sourceRoot = new URL('../', import.meta.url).href;
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier.startsWith('dayjs/plugin/') && !specifier.endsWith('.js')) return nextResolve(`${specifier}.js`, context);
    if (context.parentURL?.startsWith(sourceRoot) && specifier.startsWith('.')) {
      for (const extension of ['.ts', '.tsx']) {
        const candidate = new URL(`${new URL(specifier, context.parentURL).href}${extension}`);
        if (existsSync(fileURLToPath(candidate))) return { url: candidate.href, shortCircuit: true };
      }
    }
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (url.startsWith(sourceRoot) && /\.tsx?$/.test(url)) {
      const { outputText } = ts.transpileModule(readFileSync(fileURLToPath(url), 'utf8'), {
        fileName: fileURLToPath(url), compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2020, jsx: ts.JsxEmit.ReactJSX },
      });
      return { format: 'module', source: outputText, shortCircuit: true };
    }
    return nextLoad(url, context);
  },
});
const { RuntimeBoundary, ReadinessView } = await import('./HostSetup.tsx');
const { ScopePreviewView } = await import('./ScopeEditor.tsx');
const render = (component, props) => renderToStaticMarkup(createElement(MantineProvider, {}, createElement(component, props)));

test('runtime rendering distinguishes the container and unknown physical host without inventing an endpoint', () => {
  const html = render(RuntimeBoundary, { runtime: { kind: 'container', runtime_os: 'linux',
    local_transport: { boundary: 'container', description: 'Commands run inside this container.' }, hints: [{ code: 'reference', message: 'Use an existing service.' }] } });
  for (const phrase of ['Runtime: container', 'physical host OS and address have not been detected', 'not the physical host', 'authorized host address', 'Use an existing service']) assert.ok(html.includes(phrase), phrase);
  assert.doesNotMatch(html, /host\.docker\.internal|172\.17\.0\.1|physical host OS: linux|host detected/i);
});

test('native runtime and ready declarations remain explicit uncertainty rather than connection verification', () => {
  const native = render(RuntimeBoundary, { runtime: { kind: 'native', runtime_os: 'windows', local_transport: { description: 'This process environment.' }, hints: [] } });
  assert.match(native, /not proof of bare metal/);
  const html = render(ReadinessView, { readiness: { ready_for_connection_test: true,
    checks: [{ code: 'connection', status: 'unknown', message: 'Connectivity and credentials require a test.' }], warnings: ['Loopback refers to this runtime.'] } });
  for (const phrase of ['Declarations ready for a connection test', 'Declarations only', 'No connection, credential, privilege', 'unknown:', 'Loopback refers to this runtime']) assert.ok(html.includes(phrase), phrase);
  assert.doesNotMatch(html, /connection verified|credentials verified|scan completed/i);
});

test('scope rendering preserves exact IPv6 counts, exclusions, truncated limits and escaped normalization warnings', () => {
  const count = '340282366920938463463374607431768211456';
  const html = render(ScopePreviewView, { preview: { networks: ['fd00::/112'], network_count: 257, input_address_count: count,
    excluded_address_count: '1', address_count: '340282366920938463463374607431768211455', can_save: false, truncated: true,
    blocking_reasons: ['Too many addresses'], warnings: ['fd00::1/112 broadens to fd00::/112 <script>bad</script>'],
    normalizations: [{ field: 'include', input: 'fd00::1/112', normalized: 'fd00::/112' }, { field: 'exclude', input: '10.20.30.40/24', normalized: '10.20.30.0/24' }],
    requires_normalization_acknowledgment: true,
    limits: { max_entries: 128, max_networks: 256, max_addresses: 65536 } } });
  for (const phrase of [count, 'removed by exclusions: 1', 'Range save blocked', 'preview is truncated', 'not discovered hosts or authorized inventory assets',
    'fd00::/112', 'Too many addresses', '65536 effective addresses']) assert.ok(html.includes(phrase), phrase);
  assert.match(html, /broadens to fd00::\/112 &lt;script&gt;bad&lt;\/script&gt;/);
  assert.match(html, /CIDR broadening requires acknowledgement/);
  assert.match(html, /Exclusion: 10\.20\.30\.40\/24 expands to 10\.20\.30\.0\/24/);
  assert.doesNotMatch(html, /<script\b|3\.4028.*e\+38/);
});
