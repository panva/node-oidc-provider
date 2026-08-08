import KoaRouter from '@koa/router';
import { expect } from 'chai';

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
  it('matches the same route for every method and path', () => {
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

    expect(mismatches, mismatches.join('\n')).to.have.lengthOf(0);
  });

  it('extracts the same params', () => {
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

    expect(mismatches, mismatches.join('\n')).to.have.lengthOf(0);
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
        it(`${name} with params #${i}`, () => {
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

          expect(call(mine)).to.deep.equal(call(theirs));
        });
      }
    }
  });

  it('tolerates a trailing slash and matches case insensitively, as path-to-regexp does', () => {
    for (const path of ['/token', '/token/', '/TOKEN', '/Token/']) {
      expect(mine.match('POST', path)?.route.name, path).to.equal('token');
      expect(theirs.match(path, 'POST').route, path).to.equal(true);
    }
    // params keep the request's casing
    expect(mine.match('GET', '/REG/AbC/')?.params).to.deep.equal({ clientId: 'AbC' });
  });

  it('matches a route configured with a trailing slash', () => {
    // routes: { token: '/token/' } is permitted by the configuration
    for (const registered of ['/token', '/token/', '/reg/:id', '/reg/:id/']) {
      const a = new Router();
      const b = new KoaRouter();
      a.post('r', registered, function handler() {});
      b.post('r', registered, function handler() {});

      for (const path of ['/token', '/token/', '/token//', '/reg/abc', '/reg/abc/', '/reg/abc//']) {
        expect(
          !!a.match('POST', path),
          `registered ${registered}, requested ${path}`,
        ).to.equal(!!b.match(path, 'POST').route);
      }
    }
  });

  it('establishes the same koa context as @koa/router', async () => {
    const router = new Router();
    router.get('client', '/reg/:clientId', function handler() {});

    // as a mount or an upstream router would leave it
    const ctx = { method: 'GET', path: '/reg/AbC', params: { tenant: 'acme' }, request: {} };
    await router.routes()(ctx, () => {});

    expect(ctx.params).to.deep.equal({ tenant: 'acme', clientId: 'AbC' });
    expect(ctx.request.params).to.equal(ctx.params);
    expect(ctx.router).to.equal(router);
    expect(ctx.routerName).to.equal('client');
    expect(ctx.routerPath).to.equal('/reg/:clientId');
    expect(ctx._matchedRoute).to.equal('/reg/:clientId');
    expect(ctx._matchedRouteName).to.equal('client');
  });

  it('folds case the way a case-insensitive RegExp does, not the way toLowerCase does', () => {
    // U+212A KELVIN SIGN lowercases to `k`, but a case-insensitive RegExp
    // without the `u` flag does not fold it - so /to\u212Aen must NOT reach the
    // token endpoint, or anything in front of the provider matching on the
    // literal path can be walked around
    const a = new Router();
    const b = new KoaRouter();
    a.post('token', '/token', function handler() {});
    b.post('token', '/token', function handler() {});

    expect(!!a.match('POST', '/to\u212Aen'), 'KELVIN SIGN must not match').to.equal(false);
    expect(!!b.match('/to\u212Aen', 'POST').route).to.equal(false);

    // while ordinary ASCII and Latin-1 case folding still works, as before
    for (const path of ['/TOKEN', '/ToKeN', '/token']) {
      expect(!!a.match('POST', path), path).to.equal(!!b.match(path, 'POST').route);
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
    expect(disagreements, disagreements.join(' ')).to.have.lengthOf(0);
  });

  it('routes HEAD to GET handlers, as @koa/router does', () => {
    expect(mine.match('HEAD', '/jwks')?.route.name).to.equal('jwks');
    expect(mine.match('HEAD', '/token')).to.equal(undefined);
  });

  it('resolves a duplicated route name to the first registration', () => {
    expect(mine.url('discovery')).to.equal('/.well-known/oauth-authorization-server');
    expect(mine.url('discovery')).to.equal(theirs.url('discovery'));
  });

  it('composes the middleware stack in order and stops when one does not call next', async () => {
    const router = new Router();
    const calls = [];
    router.get('x', '/x', async (_ctx, next) => { calls.push(1); await next(); calls.push(3); }, async () => { calls.push(2); });

    const ctx = { method: 'GET', path: '/x' };
    await router.routes()(ctx, () => { calls.push('downstream'); });

    expect(calls).to.deep.equal([1, 2, 3]);
    expect(ctx._matchedRouteName).to.equal('x');
    expect(ctx.params).to.deep.equal({});
  });

  it('rejects a middleware calling next() twice, as koa-compose does', async () => {
    const router = new Router();
    router.get('x', '/x', async (_ctx, next) => { await next(); await next(); });

    let caught;
    try {
      await router.routes()({ method: 'GET', path: '/x' }, () => {});
    } catch (err) {
      caught = err;
    }

    expect(caught).to.be.instanceOf(Error);
    expect(caught.message).to.equal('next() called multiple times');
  });

  it('falls through to downstream when nothing matches', async () => {
    let downstream = false;
    await mine.routes()({ method: 'PATCH', path: '/nope' }, () => { downstream = true; });
    expect(downstream).to.equal(true);
  });
});
