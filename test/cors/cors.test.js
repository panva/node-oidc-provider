import { expect } from 'chai';

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
  expect(headers[Vary]).to.eql('Origin');
  expect(accessControlHeaders(headers)).to.eql(expected);
}

describe('CORS setup', () => {
  before(bootstrap(import.meta.url));
  before(function () { return this.login(); });
  before(async function () {
    const at = new this.provider.AccessToken({
      accountId: this.loggedInAccountId,
      grantId: this.getGrantId(),
      client: await this.provider.Client.find('client'),
      scope: 'openid',
    });

    this.token = await at.save();
  });

  describe('error handling', () => {
    before(function () {
      this.default = i(this.provider).configuration('clientBasedCORS');
    });

    after(function () {
      const conf = i(this.provider).configuration();
      conf.clientBasedCORS = this.default;
    });

    it('500s when clientBasedCORS returns non-boolean', async function () {
      i(this.provider).configuration().clientBasedCORS = () => Promise.resolve(true);
      const { status, headers } = await req.call(
        this,
        'get',
        '/me',
        'https://example.com',
        ['set', 'authorization', `Bearer ${this.token}`],
      );
      expect(status).to.eql(500);
      assertCorsHeaders(headers, {
        [ACEHeaders]: 'WWW-Authenticate',
        [ACAOrigin]: 'https://example.com',
      });
    });
  });

  it('discovery has cors open', async function () {
    const { status, headers } = await req.call(this, 'get', '/.well-known/openid-configuration', 'https://example.com');
    expect(status).to.eql(200);
    assertCorsHeaders(headers, {
      [ACAOrigin]: 'https://example.com',
    });
  });

  it('discovery preflights have cors open', async function () {
    const { status, headers } = await preflight.call(this, 'GET', '/.well-known/openid-configuration', 'https://example.com');
    expect(status).to.eql(204);
    assertCorsHeaders(headers, {
      [ACAOrigin]: 'https://example.com',
      [ACAMaxAge]: '3600',
      [ACAMethods]: 'GET',
      [ACAHeaders]: 'foo',
    });
  });

  it('jwks_uri has cors open', async function () {
    const { status, headers } = await req.call(this, 'get', '/jwks', 'https://example.com');
    expect(status).to.eql(200);
    assertCorsHeaders(headers, {
      [ACAOrigin]: 'https://example.com',
    });
  });

  it('jwks_uri preflights have cors open', async function () {
    const { status, headers } = await preflight.call(this, 'GET', '/jwks', 'https://example.com');
    expect(status).to.eql(204);
    assertCorsHeaders(headers, {
      [ACAOrigin]: 'https://example.com',
      [ACAMaxAge]: '3600',
      [ACAMethods]: 'GET',
      [ACAHeaders]: 'foo',
    });
  });

  describe('with clientBasedCORS resolving to true', () => {
    before(function () {
      const conf = i(this.provider).configuration();
      this.clientBasedCORS = conf.clientBasedCORS;
      conf.clientBasedCORS = () => true;
    });

    after(function () {
      const conf = i(this.provider).configuration();
      conf.clientBasedCORS = this.clientBasedCORS;
    });

    it('userinfo has cors open', async function () {
      const { status, headers } = await req.call(
        this,
        'get',
        '/me',
        'https://example.com',
        ['set', 'authorization', `Bearer ${this.token}`],
      );
      expect(status).to.eql(200);
      assertCorsHeaders(headers, {
        [ACEHeaders]: 'WWW-Authenticate',
        [ACAOrigin]: 'https://example.com',
      });
    });

    it('userinfo preflights have cors open', async function () {
      const { status, headers } = await preflight.call(this, 'GET', '/me', 'https://example.com');
      expect(status).to.eql(204);
      assertCorsHeaders(headers, {
        [ACAOrigin]: 'https://example.com',
        [ACAMaxAge]: '3600',
        [ACAMethods]: 'GET,POST',
        [ACAHeaders]: 'foo',
      });
    });

    it('token has cors open', async function () {
      const { status, headers } = await req.call(
        this,
        'post',
        '/token',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
        ['send', { client_id: 'client', grant_type: 'client_credentials' }],
      );
      expect(status).to.eql(200);
      assertCorsHeaders(headers, {
        [ACEHeaders]: 'WWW-Authenticate',
        [ACAOrigin]: 'https://example.com',
      });
    });

    it('token (error) has cors open', async function () {
      const { status, headers } = await req.call(
        this,
        'post',
        '/token',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
        ['send', { client_id: 'client' }],
      );
      expect(status).to.eql(400);
      assertCorsHeaders(headers, {
        [ACEHeaders]: 'WWW-Authenticate',
        [ACAOrigin]: 'https://example.com',
      });
    });

    it('token preflights have cors open', async function () {
      const { status, headers } = await preflight.call(this, 'POST', '/token', 'https://example.com');
      expect(status).to.eql(204);
      assertCorsHeaders(headers, {
        [ACAOrigin]: 'https://example.com',
        [ACAMaxAge]: '3600',
        [ACAMethods]: 'POST',
        [ACAHeaders]: 'foo',
      });
    });

    it('revocation has cors open', async function () {
      const { status, headers } = await req.call(
        this,
        'post',
        '/token/revocation',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
        ['send', { client_id: 'client', token: 'foo' }],
      );
      expect(status).to.eql(200);
      assertCorsHeaders(headers, {
        [ACEHeaders]: 'WWW-Authenticate',
        [ACAOrigin]: 'https://example.com',
      });
    });

    it('revocation preflights have cors open', async function () {
      const { status, headers } = await preflight.call(this, 'POST', '/token/revocation', 'https://example.com');
      expect(status).to.eql(204);
      assertCorsHeaders(headers, {
        [ACAOrigin]: 'https://example.com',
        [ACAMaxAge]: '3600',
        [ACAMethods]: 'POST',
        [ACAHeaders]: 'foo',
      });
    });

    it('introspection has cors open', async function () {
      const { status, headers } = await req.call(
        this,
        'post',
        '/token/introspection',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
        ['send', { client_id: 'client', token: this.token }],
      );
      expect(status).to.eql(200);
      assertCorsHeaders(headers, {
        [ACEHeaders]: 'WWW-Authenticate',
        [ACAOrigin]: 'https://example.com',
      });
    });

    it('introspection (error) has cors open', async function () {
      const { status, headers } = await req.call(
        this,
        'post',
        '/token/introspection',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
        ['send', { client_id: 'client' }],
      );
      expect(status).to.eql(400);
      assertCorsHeaders(headers, {
        [ACEHeaders]: 'WWW-Authenticate',
        [ACAOrigin]: 'https://example.com',
      });
    });

    it('introspection preflights have cors open', async function () {
      const { status, headers } = await preflight.call(this, 'POST', '/token/introspection', 'https://example.com');
      expect(status).to.eql(204);
      assertCorsHeaders(headers, {
        [ACAOrigin]: 'https://example.com',
        [ACAMaxAge]: '3600',
        [ACAMethods]: 'POST',
        [ACAHeaders]: 'foo',
      });
    });

    it('device_authorization has cors open', async function () {
      const { status, headers } = await req.call(
        this,
        'post',
        '/device/auth',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
        ['send', { client_id: 'client' }],
      );
      expect(status).to.eql(200);
      assertCorsHeaders(headers, {
        [ACEHeaders]: 'WWW-Authenticate',
        [ACAOrigin]: 'https://example.com',
      });
    });

    it('device_authorization (error) has cors open', async function () {
      const { status, headers } = await req.call(
        this,
        'post',
        '/device/auth',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
        ['send', { client_id: 'client', max_age: '-1' }],
      );
      expect(status).to.eql(400);
      assertCorsHeaders(headers, {
        [ACEHeaders]: 'WWW-Authenticate',
        [ACAOrigin]: 'https://example.com',
      });
    });

    it('device_authorization preflights have cors open', async function () {
      const { status, headers } = await preflight.call(this, 'POST', '/device/auth', 'https://example.com');
      expect(status).to.eql(204);
      assertCorsHeaders(headers, {
        [ACAOrigin]: 'https://example.com',
        [ACAMaxAge]: '3600',
        [ACAMethods]: 'POST',
        [ACAHeaders]: 'foo',
      });
    });
  });

  describe('with clientBasedCORS false (default)', () => {
    it('userinfo has cors closed', async function () {
      const { status, headers } = await req.call(
        this,
        'get',
        '/me',
        'https://example.com',
        ['set', 'authorization', `Bearer ${this.token}`],
      );
      expect(status).to.eql(400);
      assertCorsHeaders(headers, {
        // no Access-Control-Allow-Origin
        [ACEHeaders]: 'WWW-Authenticate',
      });
    });

    it('userinfo preflights have cors open', async function () {
      const { status, headers } = await preflight.call(this, 'GET', '/me', 'https://example.com');
      expect(status).to.eql(204);
      assertCorsHeaders(headers, {
        [ACAOrigin]: 'https://example.com',
        [ACAMaxAge]: '3600',
        [ACAMethods]: 'GET,POST',
        [ACAHeaders]: 'foo',
      });
    });

    it('token has cors closed', async function () {
      const { status, headers } = await req.call(
        this,
        'post',
        '/token',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
        ['send', { client_id: 'client', grant_type: 'client_credentials' }],
      );
      expect(status).to.eql(400);
      assertCorsHeaders(headers, {
        // no Access-Control-Allow-Origin
        [ACEHeaders]: 'WWW-Authenticate',
      });
    });

    it('token (error) has cors open', async function () {
      const { status, headers } = await req.call(
        this,
        'post',
        '/token',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
      );
      expect(status).to.eql(400);
      assertCorsHeaders(headers, {
        [ACEHeaders]: 'WWW-Authenticate',
        [ACAOrigin]: 'https://example.com',
      });
    });

    it('token preflights have cors open', async function () {
      const { status, headers } = await preflight.call(this, 'POST', '/token', 'https://example.com');
      expect(status).to.eql(204);
      assertCorsHeaders(headers, {
        [ACAOrigin]: 'https://example.com',
        [ACAMaxAge]: '3600',
        [ACAMethods]: 'POST',
        [ACAHeaders]: 'foo',
      });
    });

    it('revocation has cors closed', async function () {
      const { status, headers } = await req.call(
        this,
        'post',
        '/token/revocation',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
        ['send', { client_id: 'client', token: 'foo' }],
      );
      expect(status).to.eql(400);
      assertCorsHeaders(headers, {
        // no Access-Control-Allow-Origin
        [ACEHeaders]: 'WWW-Authenticate',
      });
    });

    it('revocation preflights have cors open', async function () {
      const { status, headers } = await preflight.call(this, 'POST', '/token/revocation', 'https://example.com');
      expect(status).to.eql(204);
      assertCorsHeaders(headers, {
        [ACAOrigin]: 'https://example.com',
        [ACAMaxAge]: '3600',
        [ACAMethods]: 'POST',
        [ACAHeaders]: 'foo',
      });
    });

    it('introspection has cors closed', async function () {
      const { status, headers } = await req.call(
        this,
        'post',
        '/token/introspection',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
        ['send', { client_id: 'client', token: this.token }],
      );
      expect(status).to.eql(400);
      assertCorsHeaders(headers, {
        // no Access-Control-Allow-Origin
        [ACEHeaders]: 'WWW-Authenticate',
      });
    });

    it('introspection (error) has cors open', async function () {
      const { status, headers } = await req.call(
        this,
        'post',
        '/token/introspection',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
      );
      expect(status).to.eql(400);
      assertCorsHeaders(headers, {
        [ACEHeaders]: 'WWW-Authenticate',
        [ACAOrigin]: 'https://example.com',
      });
    });

    it('introspection preflights have cors open', async function () {
      const { status, headers } = await preflight.call(this, 'POST', '/token/introspection', 'https://example.com');
      expect(status).to.eql(204);
      assertCorsHeaders(headers, {
        [ACAOrigin]: 'https://example.com',
        [ACAMaxAge]: '3600',
        [ACAMethods]: 'POST',
        [ACAHeaders]: 'foo',
      });
    });

    it('device_authorization has cors closed', async function () {
      const { status, headers } = await req.call(
        this,
        'post',
        '/device/auth',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
        ['send', { client_id: 'client' }],
      );
      expect(status).to.eql(400);
      assertCorsHeaders(headers, {
        // no Access-Control-Allow-Origin
        [ACEHeaders]: 'WWW-Authenticate',
      });
    });

    it('device_authorization (error) has cors open', async function () {
      const { status, headers } = await req.call(
        this,
        'post',
        '/device/auth',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
      );
      expect(status).to.eql(400);
      assertCorsHeaders(headers, {
        [ACEHeaders]: 'WWW-Authenticate',
        [ACAOrigin]: 'https://example.com',
      });
    });

    it('device_authorization preflights have cors open', async function () {
      const { status, headers } = await preflight.call(this, 'POST', '/device/auth', 'https://example.com');
      expect(status).to.eql(204);
      assertCorsHeaders(headers, {
        [ACAOrigin]: 'https://example.com',
        [ACAMaxAge]: '3600',
        [ACAMethods]: 'POST',
        [ACAHeaders]: 'foo',
      });
    });
  });
});
