import { describe, before, after, it } from 'node:test';
import assert from 'node:assert/strict';
import sinon from 'sinon';

import instance from '../../lib/helpers/weak_cache.js';
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
    .set('Origin', origin)
    .set('Access-Control-Request-Headers', 'foo');
}

const ACAHeaders = 'access-control-allow-headers';
const ACAMaxAge = 'access-control-max-age';
const ACAMethods = 'access-control-allow-methods';
const ACAOrigin = 'access-control-allow-origin';
const ACEHeaders = 'access-control-expose-headers';
const Vary = 'vary';

function accessControlHeaders(headers) {
  return Object.fromEntries(Object.entries(headers).filter(([header]) => header.startsWith('access-control-')));
}

function assertCorsHeaders(headers, expected) {
  assert.deepEqual(headers[Vary], 'Origin');
  assert.deepEqual(accessControlHeaders(headers), expected);
}

describe('CORS setup', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });
  before(() => fixture.login(), { timeout: 3000 });
  before(async () => {
    const at = new fixture.provider.AccessToken({
      accountId: fixture.loggedInAccountId,
      grantId: fixture.getGrantId(),
      client: await fixture.provider.Client.find('client'),
      scope: 'openid',
    });

    fixture.token = await at.save();
  }, { timeout: 3000 });

  describe('error handling', () => {
    const fixture1 = Object.create(fixture);

    before(() => {
      fixture1.default = instance(fixture1.provider).configuration.clientBasedCORS;
    }, { timeout: 3000 });

    after(() => {
      const conf = instance(fixture1.provider).configuration;
      conf.clientBasedCORS = fixture1.default;
    }, { timeout: 3000 });

    it('500s when clientBasedCORS returns non-boolean', { timeout: 3000 }, async () => {
      const spy = sinon.spy();
      fixture1.provider.once('server_error', spy);
      instance(fixture1.provider).configuration.clientBasedCORS = () => Promise.resolve(true);
      const { status, headers } = await req.call(
        fixture1,
        'get',
        '/me',
        'https://example.com',
        ['set', 'authorization', `Bearer ${fixture1.token}`],
      );
      assert.deepEqual(status, 500);
      ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'clientBasedCORS must return a Boolean'); })(spy.args[0][1]);
      assertCorsHeaders(headers, {
        [ACEHeaders]: 'WWW-Authenticate',
        [ACAOrigin]: 'https://example.com',
      });
    });
  });

  it('discovery has cors open', { timeout: 3000 }, async () => {
    const { status, headers } = await req.call(fixture, 'get', '/.well-known/openid-configuration', 'https://example.com');
    assert.deepEqual(status, 200);
    assertCorsHeaders(headers, {
      [ACAOrigin]: 'https://example.com',
    });
  });

  it('reads the current DPoP configuration when exposing response headers', { timeout: 3000 }, async () => {
    const { configuration } = instance(fixture.provider);
    const original = configuration.features.dPoP;
    const originalClientBasedCORS = configuration.clientBasedCORS;
    const request = () => req.call(
      fixture, 'get', '/me', 'https://example.com',
      ['set', 'authorization', `Bearer ${fixture.token}`],
    );

    try {
      configuration.clientBasedCORS = () => true;
      configuration.features.dPoP = { ...original, enabled: true, nonceSecret: Buffer.alloc(32) };
      const enabled = await request();
      assert.equal(enabled.status, 200);
      assert.equal(enabled.headers[ACEHeaders], 'DPoP-Nonce,WWW-Authenticate');

      configuration.features.dPoP = { ...original, enabled: false };
      const disabled = await request();
      assert.equal(disabled.status, 200);
      assert.equal(disabled.headers[ACEHeaders], 'WWW-Authenticate');
    } finally {
      configuration.features.dPoP = original;
      configuration.clientBasedCORS = originalClientBasedCORS;
    }
  });

  it('discovery preflights have cors open', { timeout: 3000 }, async () => {
    const { status, headers } = await preflight.call(fixture, 'GET', '/.well-known/openid-configuration', 'https://example.com');
    assert.deepEqual(status, 204);
    assertCorsHeaders(headers, {
      [ACAOrigin]: 'https://example.com',
      [ACAMaxAge]: '3600',
      [ACAMethods]: 'GET',
      [ACAHeaders]: 'foo',
    });
  });

  it('jwks_uri has cors open', { timeout: 3000 }, async () => {
    const { status, headers } = await req.call(fixture, 'get', '/jwks', 'https://example.com');
    assert.deepEqual(status, 200);
    assertCorsHeaders(headers, {
      [ACAOrigin]: 'https://example.com',
    });
  });

  it('jwks_uri preflights have cors open', { timeout: 3000 }, async () => {
    const { status, headers } = await preflight.call(fixture, 'GET', '/jwks', 'https://example.com');
    assert.deepEqual(status, 204);
    assertCorsHeaders(headers, {
      [ACAOrigin]: 'https://example.com',
      [ACAMaxAge]: '3600',
      [ACAMethods]: 'GET',
      [ACAHeaders]: 'foo',
    });
  });

  describe('with clientBasedCORS resolving to true', () => {
    const fixture2 = Object.create(fixture);

    before(() => {
      const conf = instance(fixture2.provider).configuration;
      fixture2.clientBasedCORS = conf.clientBasedCORS;
      conf.clientBasedCORS = () => true;
    }, { timeout: 3000 });

    after(() => {
      const conf = instance(fixture2.provider).configuration;
      conf.clientBasedCORS = fixture2.clientBasedCORS;
    }, { timeout: 3000 });

    it('userinfo has cors open', { timeout: 3000 }, async () => {
      const { status, headers } = await req.call(
        fixture2,
        'get',
        '/me',
        'https://example.com',
        ['set', 'authorization', `Bearer ${fixture2.token}`],
      );
      assert.deepEqual(status, 200);
      assertCorsHeaders(headers, {
        [ACEHeaders]: 'WWW-Authenticate',
        [ACAOrigin]: 'https://example.com',
      });
    });

    it('userinfo preflights have cors open', { timeout: 3000 }, async () => {
      const { status, headers } = await preflight.call(fixture2, 'GET', '/me', 'https://example.com');
      assert.deepEqual(status, 204);
      assertCorsHeaders(headers, {
        [ACAOrigin]: 'https://example.com',
        [ACAMaxAge]: '3600',
        [ACAMethods]: 'GET,POST',
        [ACAHeaders]: 'foo',
      });
    });

    it('token has cors open', { timeout: 3000 }, async () => {
      const { status, headers } = await req.call(
        fixture2,
        'post',
        '/token',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
        ['send', { client_id: 'client', grant_type: 'client_credentials' }],
      );
      assert.deepEqual(status, 200);
      assertCorsHeaders(headers, {
        [ACEHeaders]: 'WWW-Authenticate',
        [ACAOrigin]: 'https://example.com',
      });
    });

    it('token (error) has cors open', { timeout: 3000 }, async () => {
      const { status, headers } = await req.call(
        fixture2,
        'post',
        '/token',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
        ['send', { client_id: 'client' }],
      );
      assert.deepEqual(status, 400);
      assertCorsHeaders(headers, {
        [ACEHeaders]: 'WWW-Authenticate',
        [ACAOrigin]: 'https://example.com',
      });
    });

    it('token preflights have cors open', { timeout: 3000 }, async () => {
      const { status, headers } = await preflight.call(fixture2, 'POST', '/token', 'https://example.com');
      assert.deepEqual(status, 204);
      assertCorsHeaders(headers, {
        [ACAOrigin]: 'https://example.com',
        [ACAMaxAge]: '3600',
        [ACAMethods]: 'POST',
        [ACAHeaders]: 'foo',
      });
    });

    it('revocation has cors open', { timeout: 3000 }, async () => {
      const { status, headers } = await req.call(
        fixture2,
        'post',
        '/token/revocation',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
        ['send', { client_id: 'client', token: 'foo' }],
      );
      assert.deepEqual(status, 200);
      assertCorsHeaders(headers, {
        [ACEHeaders]: 'WWW-Authenticate',
        [ACAOrigin]: 'https://example.com',
      });
    });

    it('revocation preflights have cors open', { timeout: 3000 }, async () => {
      const { status, headers } = await preflight.call(fixture2, 'POST', '/token/revocation', 'https://example.com');
      assert.deepEqual(status, 204);
      assertCorsHeaders(headers, {
        [ACAOrigin]: 'https://example.com',
        [ACAMaxAge]: '3600',
        [ACAMethods]: 'POST',
        [ACAHeaders]: 'foo',
      });
    });

    it('introspection has cors open', { timeout: 3000 }, async () => {
      const { status, headers } = await req.call(
        fixture2,
        'post',
        '/token/introspection',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
        ['send', { client_id: 'client', token: fixture2.token }],
      );
      assert.deepEqual(status, 200);
      assertCorsHeaders(headers, {
        [ACEHeaders]: 'WWW-Authenticate',
        [ACAOrigin]: 'https://example.com',
      });
    });

    it('introspection (error) has cors open', { timeout: 3000 }, async () => {
      const { status, headers } = await req.call(
        fixture2,
        'post',
        '/token/introspection',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
        ['send', { client_id: 'client' }],
      );
      assert.deepEqual(status, 400);
      assertCorsHeaders(headers, {
        [ACEHeaders]: 'WWW-Authenticate',
        [ACAOrigin]: 'https://example.com',
      });
    });

    it('introspection preflights have cors open', { timeout: 3000 }, async () => {
      const { status, headers } = await preflight.call(fixture2, 'POST', '/token/introspection', 'https://example.com');
      assert.deepEqual(status, 204);
      assertCorsHeaders(headers, {
        [ACAOrigin]: 'https://example.com',
        [ACAMaxAge]: '3600',
        [ACAMethods]: 'POST',
        [ACAHeaders]: 'foo',
      });
    });

    it('device_authorization has cors open', { timeout: 3000 }, async () => {
      const { status, headers } = await req.call(
        fixture2,
        'post',
        '/device/auth',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
        ['send', { client_id: 'client' }],
      );
      assert.deepEqual(status, 200);
      assertCorsHeaders(headers, {
        [ACEHeaders]: 'WWW-Authenticate',
        [ACAOrigin]: 'https://example.com',
      });
    });

    it('device_authorization (error) has cors open', { timeout: 3000 }, async () => {
      const { status, headers } = await req.call(
        fixture2,
        'post',
        '/device/auth',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
        ['send', { client_id: 'client', max_age: '-1' }],
      );
      assert.deepEqual(status, 400);
      assertCorsHeaders(headers, {
        [ACEHeaders]: 'WWW-Authenticate',
        [ACAOrigin]: 'https://example.com',
      });
    });

    it('device_authorization preflights have cors open', { timeout: 3000 }, async () => {
      const { status, headers } = await preflight.call(fixture2, 'POST', '/device/auth', 'https://example.com');
      assert.deepEqual(status, 204);
      assertCorsHeaders(headers, {
        [ACAOrigin]: 'https://example.com',
        [ACAMaxAge]: '3600',
        [ACAMethods]: 'POST',
        [ACAHeaders]: 'foo',
      });
    });
  });

  describe('with clientBasedCORS false (default)', () => {
    const fixture3 = Object.create(fixture);

    it('does not allow opaque origins based on a native custom-scheme redirect URI', { timeout: 3000 }, async () => {
      const { status, headers } = await req.call(
        fixture3,
        'get',
        '/me',
        'null',
        ['set', 'authorization', `Bearer ${fixture3.token}`],
      );
      assert.deepEqual(status, 400);
      assertCorsHeaders(headers, {
        // no Access-Control-Allow-Origin
        [ACEHeaders]: 'WWW-Authenticate',
      });
    });

    it('userinfo has cors closed', { timeout: 3000 }, async () => {
      const { status, headers } = await req.call(
        fixture3,
        'get',
        '/me',
        'https://example.com',
        ['set', 'authorization', `Bearer ${fixture3.token}`],
      );
      assert.deepEqual(status, 400);
      assertCorsHeaders(headers, {
        // no Access-Control-Allow-Origin
        [ACEHeaders]: 'WWW-Authenticate',
      });
    });

    it('userinfo preflights have cors open', { timeout: 3000 }, async () => {
      const { status, headers } = await preflight.call(fixture3, 'GET', '/me', 'https://example.com');
      assert.deepEqual(status, 204);
      assertCorsHeaders(headers, {
        [ACAOrigin]: 'https://example.com',
        [ACAMaxAge]: '3600',
        [ACAMethods]: 'GET,POST',
        [ACAHeaders]: 'foo',
      });
    });

    it('token has cors closed', { timeout: 3000 }, async () => {
      const { status, headers } = await req.call(
        fixture3,
        'post',
        '/token',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
        ['send', { client_id: 'client', grant_type: 'client_credentials' }],
      );
      assert.deepEqual(status, 400);
      assertCorsHeaders(headers, {
        // no Access-Control-Allow-Origin
        [ACEHeaders]: 'WWW-Authenticate',
      });
    });

    it('token (error) has cors open', { timeout: 3000 }, async () => {
      const { status, headers } = await req.call(
        fixture3,
        'post',
        '/token',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
      );
      assert.deepEqual(status, 400);
      assertCorsHeaders(headers, {
        [ACEHeaders]: 'WWW-Authenticate',
        [ACAOrigin]: 'https://example.com',
      });
    });

    it('token preflights have cors open', { timeout: 3000 }, async () => {
      const { status, headers } = await preflight.call(fixture3, 'POST', '/token', 'https://example.com');
      assert.deepEqual(status, 204);
      assertCorsHeaders(headers, {
        [ACAOrigin]: 'https://example.com',
        [ACAMaxAge]: '3600',
        [ACAMethods]: 'POST',
        [ACAHeaders]: 'foo',
      });
    });

    it('revocation has cors closed', { timeout: 3000 }, async () => {
      const { status, headers } = await req.call(
        fixture3,
        'post',
        '/token/revocation',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
        ['send', { client_id: 'client', token: 'foo' }],
      );
      assert.deepEqual(status, 400);
      assertCorsHeaders(headers, {
        // no Access-Control-Allow-Origin
        [ACEHeaders]: 'WWW-Authenticate',
      });
    });

    it('revocation preflights have cors open', { timeout: 3000 }, async () => {
      const { status, headers } = await preflight.call(fixture3, 'POST', '/token/revocation', 'https://example.com');
      assert.deepEqual(status, 204);
      assertCorsHeaders(headers, {
        [ACAOrigin]: 'https://example.com',
        [ACAMaxAge]: '3600',
        [ACAMethods]: 'POST',
        [ACAHeaders]: 'foo',
      });
    });

    it('introspection has cors closed', { timeout: 3000 }, async () => {
      const { status, headers } = await req.call(
        fixture3,
        'post',
        '/token/introspection',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
        ['send', { client_id: 'client', token: fixture3.token }],
      );
      assert.deepEqual(status, 400);
      assertCorsHeaders(headers, {
        // no Access-Control-Allow-Origin
        [ACEHeaders]: 'WWW-Authenticate',
      });
    });

    it('introspection (error) has cors open', { timeout: 3000 }, async () => {
      const { status, headers } = await req.call(
        fixture3,
        'post',
        '/token/introspection',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
      );
      assert.deepEqual(status, 400);
      assertCorsHeaders(headers, {
        [ACEHeaders]: 'WWW-Authenticate',
        [ACAOrigin]: 'https://example.com',
      });
    });

    it('introspection preflights have cors open', { timeout: 3000 }, async () => {
      const { status, headers } = await preflight.call(fixture3, 'POST', '/token/introspection', 'https://example.com');
      assert.deepEqual(status, 204);
      assertCorsHeaders(headers, {
        [ACAOrigin]: 'https://example.com',
        [ACAMaxAge]: '3600',
        [ACAMethods]: 'POST',
        [ACAHeaders]: 'foo',
      });
    });

    it('device_authorization has cors closed', { timeout: 3000 }, async () => {
      const { status, headers } = await req.call(
        fixture3,
        'post',
        '/device/auth',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
        ['send', { client_id: 'client' }],
      );
      assert.deepEqual(status, 400);
      assertCorsHeaders(headers, {
        // no Access-Control-Allow-Origin
        [ACEHeaders]: 'WWW-Authenticate',
      });
    });

    it('device_authorization (error) has cors open', { timeout: 3000 }, async () => {
      const { status, headers } = await req.call(
        fixture3,
        'post',
        '/device/auth',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
      );
      assert.deepEqual(status, 400);
      assertCorsHeaders(headers, {
        [ACEHeaders]: 'WWW-Authenticate',
        [ACAOrigin]: 'https://example.com',
      });
    });

    it('device_authorization preflights have cors open', { timeout: 3000 }, async () => {
      const { status, headers } = await preflight.call(fixture3, 'POST', '/device/auth', 'https://example.com');
      assert.deepEqual(status, 204);
      assertCorsHeaders(headers, {
        [ACAOrigin]: 'https://example.com',
        [ACAMaxAge]: '3600',
        [ACAMethods]: 'POST',
        [ACAHeaders]: 'foo',
      });
    });
  });
});
