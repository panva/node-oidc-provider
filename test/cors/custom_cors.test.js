import { describe, before, it } from 'node:test';
import assert from 'node:assert/strict';
import cors from '@koa/cors';

import bootstrap from '../test_helper.js';

function req(verb, url, origin, ...methods) {
  const request = this.agent[verb](url)
    .set('Origin', origin);

  if (methods.length) {
    methods.forEach(([method, ...args]) => {
      request[method](...args);
    });
  }

  return request;
}

function preflight(verb, url, origin) {
  return this.agent.options(url)
    .set('Access-Control-Request-Method', verb)
    .set('Origin', origin);
}

const ACAMaxAge = 'access-control-max-age';
const ACAOrigin = 'access-control-allow-origin';

describe('CORS setup', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  before(async () => {
    fixture.provider.use(cors({
      origin: 'https://example.com',
    }));
  }, { timeout: 3000 });

  it('ignores all built-in cors then', { timeout: 3000 }, async () => {
    let { status, headers } = await preflight.call(fixture, 'GET', '/.well-known/openid-configuration', 'https://rp.example.com');
    assert.deepEqual(status, 204);
    assert.deepEqual(headers[ACAOrigin], 'https://example.com');
    assert.ok(!(ACAMaxAge in Object(headers)));

    ({ status, headers } = await req.call(
      fixture,
      'get',
      '/.well-known/openid-configuration',
      'https://rp.example.com',
    ));
    assert.deepEqual(status, 200);
    assert.deepEqual(headers[ACAOrigin], 'https://example.com');
    assert.ok(!(ACAMaxAge in Object(headers)));
  });
});
