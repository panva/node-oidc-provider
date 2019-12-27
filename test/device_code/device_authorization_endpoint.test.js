const sinon = require('sinon');
const { expect } = require('chai');

const bootstrap = require('../test_helper');
const { normalize } = require('../../lib/helpers/user_codes');

const route = '/device/auth';

describe('device_authorization_endpoint', () => {
  before(bootstrap(__dirname));

  it('rejects other than application/x-www-form-urlencoded', function () {
    const spy = sinon.spy();
    this.provider.once('device_authorization.error', spy);

    return this.agent.post(route)
      .send({
        client_id: 'client',
        scope: 'openid',
      })
      .expect(400)
      .expect('content-type', /application\/json/)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
      })
      .expect({
        error: 'invalid_request',
        error_description: 'only application/x-www-form-urlencoded content-type bodies are supported on POST /device/auth',
      });
  });

  describe('client validation', () => {
    it('only responds to clients with urn:ietf:params:oauth:grant-type:device_code enabled', function () {
      const spy = sinon.spy();
      this.provider.once('device_authorization.error', spy);

      return this.agent.post(route)
        .send({
          client_id: 'client-not-allowed',
        })
        .type('form')
        .expect(400)
        .expect('content-type', /application\/json/)
        .expect({
          error: 'unauthorized_client',
          error_description: 'urn:ietf:params:oauth:grant-type:device_code is not allowed for this client',
        })
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
        });
    });

    it('rejects invalid clients', function () {
      const spy = sinon.spy();
      this.provider.once('device_authorization.error', spy);

      return this.agent.post(route)
        .send({
          client_id: 'not-found-client',
        })
        .type('form')
        .expect(401)
        .expect('content-type', /application\/json/)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
        })
        .expect({
          error: 'invalid_client',
          error_description: 'client authentication failed',
        });
    });
  });

  describe('param validation', () => {
    ['request', 'request_uri', 'registration'].forEach((param) => {
      it(`check for not supported parameter ${param}`, function () {
        const spy = sinon.spy();
        this.provider.once('device_authorization.error', spy);

        return this.agent.post(route)
          .send({
            client_id: 'client',
            scope: 'openid',
            [param]: 'some',
          })
          .type('form')
          .expect(400)
          .expect('content-type', /application\/json/)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
          })
          .expect({
            error: `${param}_not_supported`,
            error_description: `${param} parameter provided but not supported`,
          });
      });
    });

    it('checks prompt values', function () {
      const spy = sinon.spy();
      this.provider.once('device_authorization.error', spy);

      return this.agent.post(route)
        .send({
          client_id: 'client',
          scope: 'openid',
          prompt: 'unsupported',
        })
        .type('form')
        .expect(400)
        .expect('content-type', /application\/json/)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
        })
        .expect({
          error: 'invalid_request',
          error_description: 'unsupported prompt value requested',
        });
    });

    it('checks for bad prompt combination', function () {
      const spy = sinon.spy();
      this.provider.once('device_authorization.error', spy);

      return this.agent.post(route)
        .send({
          client_id: 'client',
          scope: 'openid',
          prompt: 'none login',
        })
        .type('form')
        .expect(400)
        .expect('content-type', /application\/json/)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
        })
        .expect({
          error: 'invalid_request',
          error_description: 'prompt none must only be used alone',
        });
    });

    it('unsupported prompt', function () {
      const spy = sinon.spy();
      this.provider.once('device_authorization.error', spy);

      return this.agent.post(route)
        .send('scope=openid&scope=openid&client_id=client')
        .type('form')
        .expect(400)
        .expect('content-type', /application\/json/)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
        })
        .expect({
          error: 'invalid_request',
          error_description: "'scope' parameter must not be provided twice",
        });
    });
  });

  it('responds with json 200', async function () {
    const spy = sinon.spy();
    this.provider.once('device_authorization.success', spy);
    let response;

    await this.agent.post(route)
      .send({
        client_id: 'client',
        scope: 'openid',
        extra: 'included',
        claims: JSON.stringify({ userinfo: { email: null } }),
        redirect_uri: 'https://rp.example.com/cb/not/included',
        response_mode: 'not included',
        state: 'not included',
        response_type: 'not included',
        code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        code_challenge_method: 'S256',
      })
      .type('form')
      .expect(200)
      .expect('content-type', /application\/json/)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
      })
      .expect(({ body }) => {
        expect(body).to.have.keys([
          'device_code',
          'user_code',
          'verification_uri',
          'verification_uri_complete',
          'expires_in',
        ]);
        expect(body.verification_uri_complete).to.equal(`${body.verification_uri}?user_code=${body.user_code}`);
        expect(body).to.have.property('verification_uri').that.matches(/\/device$/);
        expect(body).to.have.property('expires_in', 600);
        response = body;
      });

    const dc = await this.provider.DeviceCode.find(response.device_code);
    expect(dc).to.be.ok;
    expect(dc).to.have.property('clientId', 'client');
    expect(dc).to.have.property('userCode').that.is.a('string').and.equals(normalize(response.user_code));
    expect(dc).to.have.property('params').that.is.an('object');
    expect(dc.params).to.have.property('client_id', 'client');
    expect(dc.params).to.have.property('scope', 'openid');
    expect(dc.params).to.have.property('extra', 'included');
    expect(dc.params).to.have.property('claims').that.equals(JSON.stringify({ userinfo: { email: null } }));
    expect(dc.params).not.to.have.property('redirect_uri');
    expect(dc.params).not.to.have.property('response_type');
    expect(dc.params).not.to.have.property('state');
    expect(dc.params).not.to.have.property('response_mode');
  });

  it('handles regular client auth', function () {
    return this.agent.post(route)
      .auth('client-basic-auth', 'secret')
      .type('form')
      .expect(200)
      .expect('content-type', /application\/json/)
      .expect(({ body }) => {
        expect(body).to.have.keys([
          'device_code',
          'user_code',
          'verification_uri',
          'verification_uri_complete',
          'expires_in',
        ]);
      });
  });

  it('populates ctx.oidc.entities', function (done) {
    this.provider.use(this.assertOnce((ctx) => {
      expect(ctx.oidc.entities).to.have.keys('Client', 'DeviceCode');
    }, done));

    this.agent.post(route)
      .send({
        client_id: 'client',
        scope: 'openid',
        code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        code_challenge_method: 'S256',
      })
      .type('form')
      .end(() => {});
  });
});
