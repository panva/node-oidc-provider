import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import KoaRouter from '@koa/router';

import Router from '../../lib/helpers/router.js';

/*
 * lib/helpers/router.js replaces @koa/router. @koa/router is kept as a
 * devDependency so the replacement can be held to it: for the route table this
 * application actually registers, both must agree on which route a request
 * matches, on the params handed to it, and on the URL that reverse lookup
 * produces.
 */

// mirrors lib/helpers/initialize_app.js, including the duplicate `discovery`
// name across two paths and the shared paths across verbs
const ROUTES = [
  ['get', 'authorization', '/auth'],
  ['post', 'authorization', '/auth'],
  ['get', 'resume', '/auth/:uid'],
  ['get', 'userinfo', '/me'],
  ['post', 'userinfo', '/me'],
  ['options', 'cors.userinfo', '/me'],
  ['post', 'token', '/token'],
  ['options', 'cors.token', '/token'],
  ['get', 'jwks', '/jwks'],
  ['options', 'cors.jwks', '/jwks'],
  ['get', 'discovery', '/.well-known/oauth-authorization-server'],
  ['options', 'cors.discovery', '/.well-known/oauth-authorization-server'],
  ['get', 'discovery', '/.well-known/openid-configuration'],
  ['options', 'cors.discovery', '/.well-known/openid-configuration'],
  ['post', 'registration', '/reg'],
  ['get', 'client', '/reg/:clientId'],
  ['put', 'client_update', '/reg/:clientId'],
  ['delete', 'client_delete', '/reg/:clientId'],
  ['post', 'revocation', '/token/revocation'],
  ['post', 'introspection', '/token/introspection'],
  ['post', 'end_session_confirm', '/session/end/confirm'],
  ['get', 'end_session', '/session/end'],
  ['post', 'end_session', '/session/end'],
  ['get', 'end_session_success', '/session/end/success'],
  ['post', 'device_authorization', '/device/auth'],
  ['get', 'code_verification', '/device'],
  ['post', 'code_verification', '/device'],
  ['get', 'device_resume', '/device/:uid'],
  ['post', 'pushed_authorization_request', '/request'],
  ['post', 'backchannel_authentication', '/backchannel'],
  ['get', 'interaction', '/interaction/:uid'],
  ['post', 'submit', '/interaction/:uid'],
  ['get', 'abort', '/interaction/:uid/abort'],
];

const build = (Class) => {
  const router = new Class();
  for (const [verb, name, path] of ROUTES) {
    router[verb](name, path, function handler() {});
  }
  return router;
};

const mine = build(Router);
const theirs = build(KoaRouter);

const REQUESTS = [];
for (const method of ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH']) {
  for (const path of [
    '/auth', '/auth/', '/auth/abc', '/auth/abc/def', '//auth',
    '/me', '/token', '/token/revocation', '/token/introspection', '/jwks',
    '/.well-known/openid-configuration', '/.well-known/oauth-authorization-server',
    '/reg', '/reg/client-id', '/reg/client id', '/reg/client%20id', '/reg/a%2Fb',
    '/reg/client-id/extra', '/session/end', '/session/end/confirm', '/session/end/success',
    '/device', '/device/auth', '/device/ABCD-1234', '/interaction/uid',
    '/interaction/uid/abort', '/interaction/uid/other', '/interaction', '/interaction/',
    '/request', '/backchannel', '/nope', '/', '', '/d', '/dev', '/devic',
    '/reg/%', '/reg/%E0%A4%A', '/auth/../token', '/AUTH',
  ]) {
    REQUESTS.push([method, path]);
  }
}

describe('router transcription', () => {
  it('matches the same route for every method and path', { timeout: 3000 }, () => {
    const mismatches = [];

    for (const [method, path] of REQUESTS) {
      const a = mine.match(method, path);
      const b = theirs.match(path, method);

      const mineName = a?.route.name;
      // @koa/router exposes the matched stack; the name of the last matching
      // layer with a name is what it would set as _matchedRouteName
      const theirLayer = b.pathAndMethod.at(-1);
      const theirName = b.route ? theirLayer?.name : undefined;

      if (mineName !== theirName) {
        mismatches.push(`${method} ${path}: mine=${mineName} theirs=${theirName}`);
      }
    }

    assert.equal(mismatches.length, 0, mismatches.join('\n'));
  });

  it('extracts the same params', { timeout: 3000 }, () => {
    const mismatches = [];

    for (const [method, path] of REQUESTS) {
      const a = mine.match(method, path);
      if (!a) continue;

      const b = theirs.match(path, method);
      const layer = b.pathAndMethod.at(-1);
      if (!layer) continue;

      const theirParams = layer.params(path, layer.captures(path), {});

      if (JSON.stringify(a.params) !== JSON.stringify(theirParams)) {
        mismatches.push(`${method} ${path}: mine=${JSON.stringify(a.params)} theirs=${JSON.stringify(theirParams)}`);
      }
    }

    assert.equal(mismatches.length, 0, mismatches.join('\n'));
  });

  describe('url()', () => {
    const NAMES = [...new Set(ROUTES.map(([, name]) => name)), 'does-not-exist'];
    const PARAMS = [
      {},
      { uid: 'abc', clientId: 'cid' },
      { uid: 'a b/c?d#e', clientId: 'a b/c?d#e' },
      { uid: 'ünïcödé', clientId: '😀' },
      { uid: '', clientId: '' },
      { query: { user_code: 'ABCD-1234' } },
      { uid: 'u', query: { user_code: 'A B&C=D' } },
      { query: 'user_code=raw&x=1' },
      { uid: 'u', query: {} },
    ];

    for (const name of NAMES) {
      for (const [i, params] of PARAMS.entries()) {
        it(`${name} with params #${i}`, { timeout: 3000 }, () => {
          // @koa/router returns an Error for an unknown name but throws for a
          // missing parameter; both have to behave the same way
          const call = (router) => {
            try {
              const value = router.url(name, params);
              return value instanceof Error
                ? { outcome: 'returned-error' }
                : { outcome: 'ok', value };
            } catch (err) {
              return { outcome: 'threw', name: err.constructor.name };
            }
          };

          assert.deepEqual(call(mine), call(theirs));
        });
      }
    }
  });

  it('tolerates a trailing slash and matches case insensitively, as path-to-regexp does', { timeout: 3000 }, () => {
    for (const path of ['/token', '/token/', '/TOKEN', '/Token/']) {
      assert.equal(mine.match('POST', path)?.route.name, 'token', path);
      assert.equal(theirs.match(path, 'POST').route, true, path);
    }
    // params keep the request's casing
    assert.deepEqual(mine.match('GET', '/REG/AbC/')?.params, { clientId: 'AbC' });
  });

  it('matches a route configured with a trailing slash', { timeout: 3000 }, () => {
    // routes: { token: '/token/' } is permitted by the configuration
    for (const registered of ['/token', '/token/', '/reg/:id', '/reg/:id/']) {
      const a = new Router();
      const b = new KoaRouter();
      a.post('r', registered, function handler() {});
      b.post('r', registered, function handler() {});

      for (const path of ['/token', '/token/', '/token//', '/reg/abc', '/reg/abc/', '/reg/abc//']) {
        assert.equal(!!a.match('POST', path), !!b.match(path, 'POST').route, `registered ${registered}, requested ${path}`);
      }
    }
  });

  it('establishes the same koa context as @koa/router', { timeout: 3000 }, async () => {
    const router = new Router();
    router.get('client', '/reg/:clientId', function handler() {});

    // as a mount or an upstream router would leave it
    const ctx = { method: 'GET', path: '/reg/AbC', params: { tenant: 'acme' }, request: {} };
    await router.routes()(ctx, () => {});

    assert.deepEqual(ctx.params, { tenant: 'acme', clientId: 'AbC' });
    assert.equal(ctx.request.params, ctx.params);
    assert.equal(ctx.router, router);
    assert.equal(ctx.routerName, 'client');
    assert.equal(ctx.routerPath, '/reg/:clientId');
    assert.equal(ctx._matchedRoute, '/reg/:clientId');
    assert.equal(ctx._matchedRouteName, 'client');
  });

  it('folds case the way a case-insensitive RegExp does, not the way toLowerCase does', { timeout: 3000 }, () => {
    // U+212A KELVIN SIGN lowercases to `k`, but a case-insensitive RegExp
    // without the `u` flag does not fold it - so /to\u212Aen must NOT reach the
    // token endpoint, or anything in front of the provider matching on the
    // literal path can be walked around
    const a = new Router();
    const b = new KoaRouter();
    a.post('token', '/token', function handler() {});
    b.post('token', '/token', function handler() {});

    assert.equal(!!a.match('POST', '/to\u212Aen'), false, 'KELVIN SIGN must not match');
    assert.equal(!!b.match('/to\u212Aen', 'POST').route, false);

    // while ordinary ASCII and Latin-1 case folding still works, as before
    for (const path of ['/TOKEN', '/ToKeN', '/token']) {
      assert.equal(!!a.match('POST', path), !!b.match(path, 'POST').route, path);
    }

    // sweep the BMP: every code point must agree with @koa/router
    const disagreements = [];
    for (let cp = 0x20; cp <= 0xffff; cp += 1) {
      if (cp >= 0xd800 && cp <= 0xdfff) continue;
      const requested = `/to${String.fromCodePoint(cp)}en`;
      let theirs;
      try { theirs = !!b.match(requested, 'POST').route; } catch { theirs = false; }
      if (!!a.match('POST', requested) !== theirs) {
        disagreements.push(`U+${cp.toString(16).toUpperCase()}`);
      }
    }
    assert.equal(disagreements.length, 0, disagreements.join(' '));
  });

  it('routes HEAD to GET handlers, as @koa/router does', { timeout: 3000 }, () => {
    assert.equal(mine.match('HEAD', '/jwks')?.route.name, 'jwks');
    assert.equal(mine.match('HEAD', '/token'), undefined);
  });

  it('resolves a duplicated route name to the first registration', { timeout: 3000 }, () => {
    assert.equal(mine.url('discovery'), '/.well-known/oauth-authorization-server');
    assert.equal(mine.url('discovery'), theirs.url('discovery'));
  });

  it('composes the middleware stack in order and stops when one does not call next', { timeout: 3000 }, async () => {
    const router = new Router();
    const calls = [];
    router.get('x', '/x', async (_ctx, next) => { calls.push(1); await next(); calls.push(3); }, async () => { calls.push(2); });

    const ctx = { method: 'GET', path: '/x' };
    await router.routes()(ctx, () => { calls.push('downstream'); });

    assert.deepEqual(calls, [1, 2, 3]);
    assert.equal(ctx._matchedRouteName, 'x');
    assert.deepEqual(ctx.params, {});
  });

  it('rejects a middleware calling next() twice, as koa-compose does', { timeout: 3000 }, async () => {
    const router = new Router();
    router.get('x', '/x', async (_ctx, next) => { await next(); await next(); });

    let caught;
    try {
      await router.routes()({ method: 'GET', path: '/x' }, () => {});
    } catch (err) {
      caught = err;
    }

    assert.ok(caught instanceof Error);
    assert.equal(caught.message, 'next() called multiple times');
  });

  it('falls through to downstream when nothing matches', { timeout: 3000 }, async () => {
    let downstream = false;
    await mine.routes()({ method: 'PATCH', path: '/nope' }, () => { downstream = true; });
    assert.equal(downstream, true);
  });
});
