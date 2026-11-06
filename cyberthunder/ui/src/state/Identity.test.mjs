import assert from 'node:assert/strict';
import test from 'node:test';
import * as React from 'react';
import { evaluate, mount, ui } from '../lib/setupTestSupport.mjs';

const metadata = evaluate(new URL('../api/identity.ts', import.meta.url));
const anonymous = { mode: 'oidc', authenticated: false, login_available: true, permissions: [] };
const signedIn = { ...anonymous, authenticated: true, csrf_token: 'fixture-csrf', permissions: ['read'],
  principal: { actor: 'human:fixture', name: 'Test reader', roles: ['viewer'], kind: 'human' } };
const response = (body) => new Response(JSON.stringify(body), { headers: { 'Content-Type': 'application/json' } });
const deferred = () => { let resolve; const promise = new Promise((r) => { resolve = r; }); return { promise, resolve }; };

function setup(t, fetcher) {
  const savedWindow = globalThis.window, savedFetch = globalThis.fetch;
  const events = new EventTarget();
  globalThis.window = Object.assign(events, { setInterval: () => 1, clearInterval() {} });
  globalThis.fetch = fetcher;
  metadata.setSessionIdentity(null);
  const app = mount((hooks) => evaluate(new URL('./Identity.tsx', import.meta.url), {
    react: { ...React, ...hooks }, '@mantine/core': ui, '../api/identity': metadata,
  }).IdentityBoundary, { children: 'private application' });
  t.after(() => { app.unmount(); metadata.setSessionIdentity(null); globalThis.window = savedWindow; globalThis.fetch = savedFetch; });
  return app;
}

test('anonymous session offers configured sign-in and never mounts private content', async (t) => {
  const app = setup(t, async () => response(anonymous));
  await app.settle();
  assert.equal(app.button('Sign in').props.href, '/auth/login');
  assert.equal(app.nodes().some((n) => n.props?.children === 'private application'), false);
});

test('verified metadata grants only listed actions and keeps credentials out of browser storage', async (t) => {
  const app = setup(t, async () => response(signedIn));
  await app.settle();
  assert.ok(app.find((n) => n.props?.children === 'private application'));
  assert.equal(metadata.sessionIdentity().principal.actor, 'human:fixture');
  assert.deepEqual(metadata.sessionHeaders('GET'), {});
  assert.deepEqual(metadata.sessionHeaders('POST'), { 'X-CSRF-Token': 'fixture-csrf' });
  assert.equal('access_token' in metadata.sessionIdentity(), false);
});

test('logout invalidates an outstanding status response before refreshing', async (t) => {
  const old = deferred(), afterLogout = deferred();
  const calls = [];
  const app = setup(t, async (url, options = {}) => {
    calls.push({ url, ...options });
    if (url === '/auth/logout') return response({ ok: true });
    const count = calls.filter((c) => c.url === '/auth/status').length;
    return count === 1 ? response(signedIn) : count === 2 ? old.promise : afterLogout.promise;
  });
  await app.settle();
  const logout = app.find((n) => typeof n.props?.logout === 'function').props.logout;
  window.dispatchEvent(new Event('ct:session-expired'));
  await app.settle();
  const closing = logout();
  await app.settle();
  old.resolve(response(signedIn));
  await app.settle();
  assert.equal(app.nodes().some((n) => n.props?.children === 'private application'), false);
  afterLogout.resolve(response(anonymous));
  await closing;
  await app.settle();
  assert.equal(metadata.sessionIdentity().authenticated, false);
  const request = calls.find((c) => c.url === '/auth/logout');
  assert.equal(request.method, 'POST');
  assert.equal(request.headers['X-CSRF-Token'], 'fixture-csrf');
});

test('unavailable or malformed session status fails closed with a retry', async (t) => {
  let body = { ...signedIn, principal: null };
  const app = setup(t, async () => response(body));
  await app.settle();
  assert.equal(metadata.sessionIdentity(), null);
  assert.equal(app.nodes().some((n) => n.props?.children === 'private application'), false);
  body = signedIn;
  await app.click('Retry');
  assert.ok(app.find((n) => n.props?.children === 'private application'));
});

test('a completed request after unmount cannot restore the prior account', async (t) => {
  const pending = deferred();
  const app = setup(t, () => pending.promise);
  await app.settle();
  app.unmount();
  pending.resolve(response(signedIn));
  await app.settle();
  assert.equal(metadata.sessionIdentity(), null);
  assert.equal(app.lateWrites(), 0);
});
