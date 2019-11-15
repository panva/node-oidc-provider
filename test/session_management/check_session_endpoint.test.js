const { expect } = require('chai');

const bootstrap = require('../test_helper');

describe('check_session_iframe', () => {
  before(bootstrap(__dirname));
  before(function () {
    this.provider.use(async (ctx, next) => {
      ctx.response.set('X-Frame-Options', 'SAMEORIGIN');
      ctx.response.set('Content-Security-Policy', "default-src 'none'; frame-ancestors 'self' example.com *.example.net; script-src 'self' 'nonce-foo'; connect-src 'self'; img-src 'self'; style-src 'self';");
      await next();
    });
  });
  before(function () {
    const { scriptNonce: orig } = i(this.provider).configuration('features.sessionManagement');
    this.orig = orig;
  });

  afterEach(function () {
    i(this.provider).configuration('features.sessionManagement').scriptNonce = this.orig;
  });

  it('responds with frameable html', async function () {
    await this.agent.get('/session/check')
      .expect(200)
      .expect('content-type', /text\/html/)
      .expect((response) => {
        expect(response.headers['x-frame-options']).not.to.be.ok;
        expect(response.headers['content-security-policy']).not.to.match(/frame-ancestors/);
        expect(response.text).not.to.contain('nonce="foo"');
      });

    i(this.provider).configuration('features.sessionManagement').scriptNonce = (ctx) => {
      expect(ctx.oidc).to.be.ok;
      return 'foo';
    };

    return this.agent.get('/session/check')
      .expect(200)
      .expect('content-type', /text\/html/)
      .expect((response) => {
        expect(response.headers['x-frame-options']).not.to.be.ok;
        expect(response.headers['content-security-policy']).not.to.match(/frame-ancestors/);
        expect(response.text).to.contain('nonce="foo"');
      });
  });

  it('does not populate ctx.oidc.entities', function (done) {
    this.provider.use(this.assertOnce((ctx) => {
      expect(ctx.oidc.entities).to.be.empty;
    }, done));

    this.agent.get('/session/check').end(() => {});
  });
});

describe('check_session_endpoint origin check', () => {
  before(bootstrap(__dirname));

  it('responds with a 204 when origin is allowed for a client_id', function () {
    return this.agent.post('/session/check')
      .send({ client_id: 'client', origin: 'https://client.example.com' })
      .expect(204)
      .expect('');
  });

  it('does populate ctx.oidc.entities', function (done) {
    this.provider.use(this.assertOnce((ctx) => {
      expect(ctx.oidc.entities).to.have.keys('Client');
    }, done));

    this.agent.post('/session/check')
      .send({ client_id: 'client', origin: 'https://client.example.com' })
      .end(() => {});
  });

  it('checks that origin and client_id are provided', async function () {
    await this.agent.post('/session/check')
      .send({ client_id: 'client' })
      .expect(400)
      .expect({
        error: 'invalid_request',
        error_description: "missing required parameter 'origin'",
      });
    await this.agent.post('/session/check')
      .send({ origin: 'https://client.example.com' })
      .expect(400)
      .expect({
        error: 'invalid_request',
        error_description: "missing required parameter 'client_id'",
      });
    await this.agent.post('/session/check')
      .send({})
      .expect(400)
      .expect({
        error: 'invalid_request',
        error_description: "missing required parameters 'origin' and 'client_id'",
      });
  });

  it('checks that origin and client_id are strings', async function () {
    await this.agent.post('/session/check')
      .send({ client_id: 1, origin: 'https://client.example.com' })
      .expect(400)
      .expect({
        error: 'invalid_request',
        error_description: 'only string parameter values are expected',
      });
    await this.agent.post('/session/check')
      .send({ client_id: 'client', origin: 1 })
      .expect(400)
      .expect({
        error: 'invalid_request',
        error_description: 'only string parameter values are expected',
      });
  });

  it('checks the client is a valid one', async function () {
    await this.agent.post('/session/check')
      .send({ client_id: 'not-found-client', origin: 'https://client.example.com' })
      .expect(400)
      .expect({
        error: 'invalid_client',
        error_description: 'client is invalid',
      });
  });

  it('checks the client has a given origin amongst its redirect_uris origins', async function () {
    await this.agent.post('/session/check')
      .send({ client_id: 'client', origin: 'https://example.com' })
      .expect(403)
      .expect({
        error: 'invalid_request',
        error_description: 'origin not allowed',
      });
  });
});
