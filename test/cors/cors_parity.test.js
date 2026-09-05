import cors from '@koa/cors';
import { expect } from 'chai';
import Koa from 'koa';

import mine from '../../lib/shared/cors.js';

/*
 * lib/shared/cors.js used to delegate to @koa/cors. @koa/cors is kept as a
 * devDependency so the transcription can be held to it: for every profile
 * oidc-provider configures and every request shape it can see, both must emit
 * exactly the same response headers and the same status.
 */

const theirs = (options) => cors({
  keepHeadersOnError: false,
  origin(ctx) { return ctx.get('Origin') || '*'; },
  ...options,
});

// the profiles lib/helpers/initialize_app.js builds
const PROFILES = {
  open: { allowMethods: 'GET', maxAge: 3600 },
  challenge: { allowMethods: 'POST', maxAge: 3600, exposeHeaders: 'WWW-Authenticate' },
  userinfo: { allowMethods: 'GET,POST', maxAge: 3600, exposeHeaders: 'WWW-Authenticate,DPoP-Nonce' },
  client: { allowMethods: 'POST', maxAge: 3600, exposeHeaders: 'WWW-Authenticate' },
  arrays: { allowMethods: ['GET', 'POST'], maxAge: 600, exposeHeaders: ['A', 'B'] },
  bare: {},
  noMaxAge: { allowMethods: 'GET' },
};

const REQUESTS = [
  { name: 'simple GET with Origin', method: 'GET', headers: { origin: 'https://rp.example.com' } },
  { name: 'simple GET without Origin', method: 'GET', headers: {} },
  { name: 'simple POST with Origin', method: 'POST', headers: { origin: 'https://rp.example.com' } },
  { name: 'null Origin', method: 'GET', headers: { origin: 'null' } },
  { name: 'empty Origin', method: 'GET', headers: { origin: '' } },
  {
    name: 'preflight',
    method: 'OPTIONS',
    headers: { origin: 'https://rp.example.com', 'access-control-request-method': 'POST' },
  },
  {
    name: 'preflight with requested headers',
    method: 'OPTIONS',
    headers: {
      origin: 'https://rp.example.com',
      'access-control-request-method': 'POST',
      'access-control-request-headers': 'authorization,dpop',
    },
  },
  {
    name: 'preflight without Access-Control-Request-Method',
    method: 'OPTIONS',
    headers: { origin: 'https://rp.example.com' },
  },
  { name: 'OPTIONS without Origin', method: 'OPTIONS', headers: {} },
  {
    name: 'preflight without Origin',
    method: 'OPTIONS',
    headers: { 'access-control-request-method': 'POST' },
  },
];

async function run(middleware, { method, headers }, { throws = false } = {}) {
  const app = new Koa();
  const ctx = app.createContext(
    { method, headers, url: '/', socket: { encrypted: false } },
    { getHeader() {}, setHeader() {}, removeHeader() {}, hasHeader() { return false; } },
  );

  let downstream = false;
  let caught;
  try {
    await middleware(ctx, async () => {
      downstream = true;
      if (throws) {
        const err = new Error('boom');
        err.headers = { 'x-existing': '1' };
        throw err;
      }
      ctx.status = 200;
    });
  } catch (err) {
    caught = err;
  }

  return {
    headers: ctx.response.headers,
    status: ctx.status,
    downstream,
    errHeaders: caught?.headers,
  };
}

describe('cors transcription', () => {
  for (const [profile, options] of Object.entries(PROFILES)) {
    for (const request of REQUESTS) {
      it(`${profile}: ${request.name}`, async () => {
        const a = await run(mine(options), request);
        const b = await run(theirs(options), request);

        expect(a.headers, 'response headers').to.deep.equal(b.headers);
        expect(a.status, 'status').to.equal(b.status);
        expect(a.downstream, 'called downstream').to.equal(b.downstream);
      });
    }

    it(`${profile}: does not attach CORS headers to a thrown error`, async () => {
      const request = { method: 'GET', headers: { origin: 'https://rp.example.com' } };
      const a = await run(mine(options), request, { throws: true });
      const b = await run(theirs(options), request, { throws: true });

      expect(a.errHeaders).to.deep.equal(b.errHeaders);
      expect(a.headers).to.deep.equal(b.headers);
    });
  }
});
