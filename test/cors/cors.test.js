const { expect } = require('chai');

const bootstrap = require('../test_helper');

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

describe('CORS setup', () => {
  before(bootstrap(__dirname));

  before(async function () {
    const at = new this.provider.AccessToken({
      accountId: 'accountId',
      grantId: 'foo',
      clientId: 'client',
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
      expect(headers[Vary]).to.eql('Origin');
      expect(headers[ACEHeaders]).to.eql('WWW-Authenticate');
      expect(headers[ACAOrigin]).to.eql('https://example.com');
    });
  });

  it('discovery has cors open', async function () {
    const { status, headers } = await req.call(this, 'get', '/.well-known/openid-configuration', 'https://example.com');
    expect(status).to.eql(200);
    expect(headers[Vary]).to.eql('Origin');
    expect(headers[ACAOrigin]).to.eql('https://example.com');
  });

  it('discovery preflights have cors open', async function () {
    const { status, headers } = await preflight.call(this, 'GET', '/.well-known/openid-configuration', 'https://example.com');
    expect(status).to.eql(204);
    expect(headers[Vary]).to.eql('Origin');
    expect(headers[ACAOrigin]).to.eql('https://example.com');
    expect(headers[ACAMaxAge]).to.eql('3600');
    expect(headers[ACAMethods]).to.eql('GET');
    expect(headers[ACAHeaders]).to.eql('foo');
  });

  it('jwks_uri has cors open', async function () {
    const { status, headers } = await req.call(this, 'get', '/jwks', 'https://example.com');
    expect(status).to.eql(200);
    expect(headers[Vary]).to.eql('Origin');
    expect(headers[ACAOrigin]).to.eql('https://example.com');
  });

  it('jwks_uri preflights have cors open', async function () {
    const { status, headers } = await preflight.call(this, 'GET', '/jwks', 'https://example.com');
    expect(status).to.eql(204);
    expect(headers[Vary]).to.eql('Origin');
    expect(headers[ACAOrigin]).to.eql('https://example.com');
    expect(headers[ACAMaxAge]).to.eql('3600');
    expect(headers[ACAMethods]).to.eql('GET');
    expect(headers[ACAHeaders]).to.eql('foo');
  });

  describe('with clientBasedCORS true (default)', () => {
    it('userinfo has cors open', async function () {
      const { status, headers } = await req.call(
        this,
        'get',
        '/me',
        'https://example.com',
        ['set', 'authorization', `Bearer ${this.token}`],
      );
      expect(status).to.eql(200);
      expect(headers[Vary]).to.eql('Origin');
      expect(headers[ACEHeaders]).to.eql('WWW-Authenticate');
      expect(headers[ACAOrigin]).to.eql('https://example.com');
    });

    it('userinfo preflights have cors open', async function () {
      const { status, headers } = await preflight.call(this, 'GET', '/me', 'https://example.com');
      expect(status).to.eql(204);
      expect(headers[Vary]).to.eql('Origin');
      expect(headers[ACAOrigin]).to.eql('https://example.com');
      expect(headers[ACAMaxAge]).to.eql('3600');
      expect(headers[ACAMethods]).to.eql('GET,POST');
      expect(headers[ACAHeaders]).to.eql('foo');
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
      expect(headers[Vary]).to.eql('Origin');
      expect(headers[ACEHeaders]).to.eql('WWW-Authenticate');
      expect(headers[ACAOrigin]).to.eql('https://example.com');
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
      expect(headers[Vary]).to.eql('Origin');
      expect(headers[ACEHeaders]).to.eql('WWW-Authenticate');
      expect(headers[ACAOrigin]).to.eql('https://example.com');
    });

    it('token preflights have cors open', async function () {
      const { status, headers } = await preflight.call(this, 'POST', '/token', 'https://example.com');
      expect(status).to.eql(204);
      expect(headers[Vary]).to.eql('Origin');
      expect(headers[ACAOrigin]).to.eql('https://example.com');
      expect(headers[ACAMaxAge]).to.eql('3600');
      expect(headers[ACAMethods]).to.eql('POST');
      expect(headers[ACAHeaders]).to.eql('foo');
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
      expect(headers[Vary]).to.eql('Origin');
      expect(headers[ACEHeaders]).to.eql('WWW-Authenticate');
      expect(headers[ACAOrigin]).to.eql('https://example.com');
    });

    it('revocation preflights have cors open', async function () {
      const { status, headers } = await preflight.call(this, 'POST', '/token/revocation', 'https://example.com');
      expect(status).to.eql(204);
      expect(headers[Vary]).to.eql('Origin');
      expect(headers[ACAOrigin]).to.eql('https://example.com');
      expect(headers[ACAMaxAge]).to.eql('3600');
      expect(headers[ACAMethods]).to.eql('POST');
      expect(headers[ACAHeaders]).to.eql('foo');
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
      expect(headers[Vary]).to.eql('Origin');
      expect(headers[ACEHeaders]).to.eql('WWW-Authenticate');
      expect(headers[ACAOrigin]).to.eql('https://example.com');
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
      expect(headers[Vary]).to.eql('Origin');
      expect(headers[ACEHeaders]).to.eql('WWW-Authenticate');
      expect(headers[ACAOrigin]).to.eql('https://example.com');
    });

    it('introspection preflights have cors open', async function () {
      const { status, headers } = await preflight.call(this, 'POST', '/token/introspection', 'https://example.com');
      expect(status).to.eql(204);
      expect(headers[Vary]).to.eql('Origin');
      expect(headers[ACAOrigin]).to.eql('https://example.com');
      expect(headers[ACAMaxAge]).to.eql('3600');
      expect(headers[ACAMethods]).to.eql('POST');
      expect(headers[ACAHeaders]).to.eql('foo');
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
      expect(headers[Vary]).to.eql('Origin');
      expect(headers[ACEHeaders]).to.eql('WWW-Authenticate');
      expect(headers[ACAOrigin]).to.eql('https://example.com');
    });

    it('device_authorization (error) has cors open', async function () {
      const { status, headers } = await req.call(
        this,
        'post',
        '/device/auth',
        'https://example.com',
        ['set', 'content-type', 'application/x-www-form-urlencoded'],
        ['type', 'form'],
        ['send', { client_id: 'client', prompt: 'none login' }],
      );
      expect(status).to.eql(400);
      expect(headers[Vary]).to.eql('Origin');
      expect(headers[ACEHeaders]).to.eql('WWW-Authenticate');
      expect(headers[ACAOrigin]).to.eql('https://example.com');
    });

    it('device_authorization preflights have cors open', async function () {
      const { status, headers } = await preflight.call(this, 'POST', '/device/auth', 'https://example.com');
      expect(status).to.eql(204);
      expect(headers[Vary]).to.eql('Origin');
      expect(headers[ACAOrigin]).to.eql('https://example.com');
      expect(headers[ACAMaxAge]).to.eql('3600');
      expect(headers[ACAMethods]).to.eql('POST');
      expect(headers[ACAHeaders]).to.eql('foo');
    });
  });

  describe('with clientBasedCORS false', () => {
    before(function () {
      const conf = i(this.provider).configuration();
      conf.clientBasedCORS = () => false;
    });

    after(function () {
      const conf = i(this.provider).configuration();
      conf.clientBasedCORS = () => true;
    });

    it('userinfo has cors closed', async function () {
      const { status, headers } = await req.call(
        this,
        'get',
        '/me',
        'https://example.com',
        ['set', 'authorization', `Bearer ${this.token}`],
      );
      expect(status).to.eql(400);
      expect(headers[Vary]).to.eql('Origin');
      expect(headers[ACEHeaders]).to.eql('WWW-Authenticate');
      expect(headers).not.to.have.property(ACAOrigin);
    });

    it('userinfo preflights have cors open', async function () {
      const { status, headers } = await preflight.call(this, 'GET', '/me', 'https://example.com');
      expect(status).to.eql(204);
      expect(headers[Vary]).to.eql('Origin');
      expect(headers[ACAOrigin]).to.eql('https://example.com');
      expect(headers[ACAMaxAge]).to.eql('3600');
      expect(headers[ACAMethods]).to.eql('GET,POST');
      expect(headers[ACAHeaders]).to.eql('foo');
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
      expect(headers[Vary]).to.eql('Origin');
      expect(headers[ACEHeaders]).to.eql('WWW-Authenticate');
      expect(headers).not.to.have.property(ACAOrigin);
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
      expect(headers[Vary]).to.eql('Origin');
      expect(headers[ACEHeaders]).to.eql('WWW-Authenticate');
      expect(headers[ACAOrigin]).to.eql('https://example.com');
    });

    it('token preflights have cors open', async function () {
      const { status, headers } = await preflight.call(this, 'POST', '/token', 'https://example.com');
      expect(status).to.eql(204);
      expect(headers[Vary]).to.eql('Origin');
      expect(headers[ACAOrigin]).to.eql('https://example.com');
      expect(headers[ACAMaxAge]).to.eql('3600');
      expect(headers[ACAMethods]).to.eql('POST');
      expect(headers[ACAHeaders]).to.eql('foo');
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
      expect(headers[Vary]).to.eql('Origin');
      expect(headers[ACEHeaders]).to.eql('WWW-Authenticate');
      expect(headers).not.to.have.property(ACAOrigin);
    });

    it('revocation preflights have cors open', async function () {
      const { status, headers } = await preflight.call(this, 'POST', '/token/revocation', 'https://example.com');
      expect(status).to.eql(204);
      expect(headers[Vary]).to.eql('Origin');
      expect(headers[ACAOrigin]).to.eql('https://example.com');
      expect(headers[ACAMaxAge]).to.eql('3600');
      expect(headers[ACAMethods]).to.eql('POST');
      expect(headers[ACAHeaders]).to.eql('foo');
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
      expect(headers[Vary]).to.eql('Origin');
      expect(headers[ACEHeaders]).to.eql('WWW-Authenticate');
      expect(headers).not.to.have.property(ACAOrigin);
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
      expect(headers[Vary]).to.eql('Origin');
      expect(headers[ACEHeaders]).to.eql('WWW-Authenticate');
      expect(headers[ACAOrigin]).to.eql('https://example.com');
    });

    it('introspection preflights have cors open', async function () {
      const { status, headers } = await preflight.call(this, 'POST', '/token/introspection', 'https://example.com');
      expect(status).to.eql(204);
      expect(headers[Vary]).to.eql('Origin');
      expect(headers[ACAOrigin]).to.eql('https://example.com');
      expect(headers[ACAMaxAge]).to.eql('3600');
      expect(headers[ACAMethods]).to.eql('POST');
      expect(headers[ACAHeaders]).to.eql('foo');
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
      expect(headers[Vary]).to.eql('Origin');
      expect(headers[ACEHeaders]).to.eql('WWW-Authenticate');
      expect(headers).not.to.have.property(ACAOrigin);
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
      expect(headers[Vary]).to.eql('Origin');
      expect(headers[ACEHeaders]).to.eql('WWW-Authenticate');
      expect(headers[ACAOrigin]).to.eql('https://example.com');
    });

    it('device_authorization preflights have cors open', async function () {
      const { status, headers } = await preflight.call(this, 'POST', '/device/auth', 'https://example.com');
      expect(status).to.eql(204);
      expect(headers[Vary]).to.eql('Origin');
      expect(headers[ACAOrigin]).to.eql('https://example.com');
      expect(headers[ACAMaxAge]).to.eql('3600');
      expect(headers[ACAMethods]).to.eql('POST');
      expect(headers[ACAHeaders]).to.eql('foo');
    });
  });
});
