import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import ts from 'typescript';
const source = await readFile(new URL('./linkPresentation.ts', import.meta.url), 'utf8');
const { outputText } = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext } });
const { linkLabel, rateLabel } = await import('data:text/javascript;base64,' + Buffer.from(outputText).toString('base64'));

test('legacy configured values never masquerade as observations', () => {
  const old = { kbps: 56, latency_ms: 500, connected: true };
  assert.equal(linkLabel(old), 'Reachability unknown');
  assert.equal(rateLabel(old), 'Observed application rate unknown');
});
test('offline, test state, and measured application rates stay distinct', () => {
  assert.equal(linkLabel({ offline_override: true, mode: 'test' }), 'Operator offline');
  assert.equal(linkLabel({ mode: 'test', test_connected: false }), 'TEST: disconnected');
  assert.match(rateLabel({ mode: 'test', kbps: 56, latency_ms: 500 }), /^TEST estimate:/);
  assert.equal(linkLabel({ reachability: 'reachable' }), 'Endpoint observed reachable');
  assert.equal(rateLabel({ observed_kbps: 9.6 }), 'Observed application rate: 9.6 kbps');
});
