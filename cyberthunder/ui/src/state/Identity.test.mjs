import assert from 'node:assert/strict';
import test from 'node:test';
import * as React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import * as Mantine from '@mantine/core';
import { evaluate, mount, ui } from '../lib/setupTestSupport.mjs';

const metadata = evaluate(new URL('../api/identity.ts', import.meta.url));
const anonymous = { mode: 'oidc', authenticated: false, login_available: true, permissions: [] };
const signedIn = { ...anonymous, authenticated: true, csrf_token: 'fixture-csrf', permissions: ['read'],
  principal: { actor: 'human:fixture', name: 'Test reader', roles: ['viewer'], kind: 'human' } };
const response = (body) => new Response(JSON.stringify(body), { headers: { 'Content-Type': 'application/json' } });
const deferred = () => { let resolve; const promise = new Promise((r) => { resolve = r; }); return { promise, resolve }; };
const hasPrivateView = app => app.nodes().some(n => [n.props?.children].flat().includes('private application'));

test('the real identity provider connects account permissions to action controls', () => {
  const gate = evaluate(new URL('../components/PermissionGate.tsx', import.meta.url), {
    '@mantine/core': Mantine,
  });
  const { IdentityProvider } = evaluate(new URL('./Identity.tsx', import.meta.url), {
    '../components/PermissionGate': gate,
  });
  const h = React.createElement;
  const render = (identity) => renderToStaticMarkup(h(Mantine.MantineProvider, {},
    h(IdentityProvider, { identity, logout: async () => {} },
      h(gate.PermissionButton, { action: 'apply' }, 'Apply'))));
  const button = (html) => [...html.matchAll(/<button\b[^>]*>[\s\S]*?<\/button>/g)]
    .map((match) => match[0]).find((tag) => tag.includes('>Apply<'));
  const disabled = /\sdisabled(?:=|\s|>)/;
  const denied = render(signedIn);
  assert.match(button(denied), disabled);
  assert.match(denied, /apply permission required/);
  assert.doesNotMatch(denied, /Account permissions are unavailable/);
  assert.doesNotMatch(button(render({ ...signedIn, permissions: ['read', 'apply'] })), disabled);
  assert.match(button(render({ ...signedIn, permissions: ['admin'] })), disabled);
  assert.doesNotMatch(button(render({ ...anonymous, mode: 'dev' })), disabled);
});

function setup(t, fetcher) {
  const savedWindow = globalThis.window, savedFetch = globalThis.fetch;
  const events = new EventTarget();
  globalThis.window = Object.assign(events, { setInterval: () => 1, clearInterval() {},
    location: { pathname: '/decisions', search: '?proposal=change', hash: '#impact', assign() {} } });
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
  assert.equal(hasPrivateView(app), false);
});

test('verified metadata grants only listed actions and keeps credentials out of browser storage', async (t) => {
  const app = setup(t, async () => response(signedIn));
  await app.settle();
  assert.ok(hasPrivateView(app));
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
  assert.equal(hasPrivateView(app), false);
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
  assert.equal(hasPrivateView(app), false);
  body = signedIn;
  await app.click('Retry');
  assert.ok(hasPrivateView(app));
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

const stepUp = { reason: 'authentication_too_old', max_age: 300, acr_values: ['urn:ct:test:strong'] };

test('challenge keeps the current view and only a deliberate click starts bound reauthentication', async t => {
  const calls = [], destinations = [], pending = deferred();
  const app = setup(t, async (url, options) => {
    calls.push([url, options]);
    return url === '/auth/status' ? response(signedIn) : pending.promise;
  });
  window.location.assign = value => destinations.push(value);
  await app.settle();
  metadata.stepUpRequired(stepUp); await app.settle();
  assert.ok(hasPrivateView(app));
  assert.equal(app.find(n => n.type === 'Modal').props.opened, true);
  assert.equal(calls.length, 1);
  assert.deepEqual(destinations, []);
  await app.click('Reauthenticate'); await app.click('Reauthenticate');
  assert.equal(calls.length, 2);
  const [url, options] = calls[1];
  assert.equal(url, '/auth/reauthenticate');
  assert.equal(options.method, 'POST');
  assert.equal(options.headers['X-CSRF-Token'], 'fixture-csrf');
  assert.deepEqual(JSON.parse(options.body), { return_to: '/decisions?proposal=change#impact' });
  pending.resolve(response({ authorization_url: 'https://identity.example/authorize?state=server-generated' }));
  await app.settle();
  assert.deepEqual(destinations, ['https://identity.example/authorize?state=server-generated']);
  assert.equal(calls.length, 2, 'Neither a mutation nor another login was replayed');
});

test('declining reauthentication keeps the view and makes no request', async t => {
  const calls = [];
  const app = setup(t, async url => { calls.push(url); return response(signedIn); });
  await app.settle(); metadata.stepUpRequired(stepUp); await app.settle();
  await app.click('Keep reviewing');
  assert.equal(app.find(n => n.type === 'Modal').props.opened, false);
  assert.ok(hasPrivateView(app));
  assert.deepEqual(calls, ['/auth/status']);
});

test('failed reauthentication and unsafe destinations stay visible without redirect or replay', async t => {
  const destinations = [];
  const app = setup(t, async url => url === '/auth/status' ? response(signedIn) : response({ authorization_url: 'javascript:alert(1)' }));
  window.location.assign = value => destinations.push(value);
  await app.settle(); metadata.stepUpRequired(stepUp); await app.settle();
  await app.click('Reauthenticate');
  assert.deepEqual(destinations, []);
  assert.ok(app.nodes().some(n => n.props?.children === 'Reauthentication could not be started. Refresh sign-in and try again.'));
  assert.equal(metadata.sessionIdentity().authenticated, true);
});

test('a late reauthentication response cannot redirect after unmount', async t => {
  const pending = deferred(), destinations = [];
  const app = setup(t, url => url === '/auth/status' ? response(signedIn) : pending.promise);
  window.location.assign = value => destinations.push(value);
  await app.settle(); metadata.stepUpRequired(stepUp); await app.settle();
  await app.click('Reauthenticate'); app.unmount();
  pending.resolve(response({ authorization_url: 'https://identity.example/authorize' }));
  await app.settle();
  assert.deepEqual(destinations, []);
  assert.equal(app.lateWrites(), 0);
});
