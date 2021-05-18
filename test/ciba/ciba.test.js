const { strict: assert } = require('assert');

const sinon = require('sinon');
const { expect } = require('chai');
const nock = require('nock');

const { AccessDenied } = require('../../lib/helpers/errors');
const bootstrap = require('../test_helper');

describe('configuration features.ciba', () => {
  before(bootstrap(__dirname));

  afterEach(() => {
    expect(nock.isDone()).to.be.true;
  });

  it('extends discovery', function () {
    return this.agent.get('/.well-known/openid-configuration')
      .expect(200)
      .expect((response) => {
        expect(response.body).to.have.property('backchannel_authentication_endpoint').matches(/\/backchannel$/);
        expect(response.body).to.have.property('backchannel_authentication_request_signing_alg_values_supported').not.contains('none').not.contains('HS256');
        expect(response.body).to.have.property('backchannel_token_delivery_modes_supported').deep.equal(['poll', 'ping']);
        expect(response.body).to.have.property('backchannel_user_code_parameter_supported', true);
      });
  });

  describe('Provider.prototype.backchannelResult', () => {
    it('"request" can be a string (BackchannelAuthenticationRequest jti)', async function () {
      const result = new AccessDenied();
      const request = new this.provider.BackchannelAuthenticationRequest({ clientId: 'client' });
      await request.save();
      await this.provider.backchannelResult(request.jti, result);
      return assert.rejects(this.provider.backchannelResult('notfound', result), { name: 'Error', message: 'BackchannelAuthenticationRequest not found' });
    });

    it('"request" can be a BackchannelAuthenticationRequest instance', async function () {
      const result = new this.provider.Grant({ clientId: 'client', accountId: 'accountId' });
      const request = new this.provider.BackchannelAuthenticationRequest({ clientId: 'client', accountId: 'accountId' });
      await request.save();
      return this.provider.backchannelResult(request, result);
    });

    it('"request" must be a supported type', async function () {
      const result = new AccessDenied();
      // eslint-disable-next-line no-restricted-syntax
      for (const request of [{}, [], 0, 1, true, false, new Set(), new Error()]) {
        // eslint-disable-next-line no-await-in-loop
        await assert.rejects(this.provider.backchannelResult(request, result), { name: 'TypeError', message: 'invalid "request" argument' });
      }
    });

    it('"result" can be a string (Grant jti)', async function () {
      const result = new this.provider.Grant({ clientId: 'client', accountId: 'accountId' });
      const request = new this.provider.BackchannelAuthenticationRequest({ clientId: 'client', accountId: 'accountId' });
      await result.save();
      await this.provider.backchannelResult(request, result.jti);
      return assert.rejects(this.provider.backchannelResult(request, 'notfound'), { name: 'Error', message: 'Grant not found' });
    });

    it('"result" must be a supported type', async function () {
      const request = new this.provider.BackchannelAuthenticationRequest({ clientId: 'client' });
      // eslint-disable-next-line no-restricted-syntax
      for (const result of [{}, [], 0, 1, true, false, new Set(), new Error()]) {
        // eslint-disable-next-line no-await-in-loop
        await assert.rejects(this.provider.backchannelResult(request, result), { name: 'TypeError', message: 'invalid "result" argument' });
      }
    });

    it('request.clientId must be a valid client', async function () {
      const result = new AccessDenied();
      const request = new this.provider.BackchannelAuthenticationRequest({ clientId: 'notfound' });
      return assert.rejects(this.provider.backchannelResult(request, result), { name: 'Error', message: 'Client not found' });
    });

    it('request.clientId must match result.clientId', async function () {
      const result = new this.provider.Grant({ clientId: 'client', accountId: 'accountId' });
      const request = new this.provider.BackchannelAuthenticationRequest({ clientId: 'client-ping', accountId: 'accountId' });
      return assert.rejects(this.provider.backchannelResult(request, result), { name: 'Error', message: 'client mismatch' });
    });

    it('request.accountId must match result.accountId', async function () {
      const result = new this.provider.Grant({ clientId: 'client', accountId: 'accountId' });
      const request = new this.provider.BackchannelAuthenticationRequest({ clientId: 'client', accountId: 'accountId-2' });
      return assert.rejects(this.provider.backchannelResult(request, result), { name: 'Error', message: 'accountId mismatch' });
    });

    it('saves the "request"', async function () {
      const result = new this.provider.Grant({ clientId: 'client', accountId: 'accountId' });
      const request = new this.provider.BackchannelAuthenticationRequest({ clientId: 'client', accountId: 'accountId' });
      expect(request.jti).not.to.be.ok;
      await this.provider.backchannelResult(request, result);
      expect(request.jti).to.be.ok;
    });

    it('pings the client (204)', async function () {
      const result = new this.provider.Grant({ clientId: 'client-ping', accountId: 'accountId' });
      const request = new this.provider.BackchannelAuthenticationRequest({ clientId: 'client-ping', accountId: 'accountId', params: { client_notification_token: 'foo' } });
      nock('https://rp.example.com/')
        .post('/ping')
        .reply(204);
      await this.provider.backchannelResult(request, result);
    });

    it('pings the client (200)', async function () {
      const result = new this.provider.Grant({ clientId: 'client-ping', accountId: 'accountId' });
      const request = new this.provider.BackchannelAuthenticationRequest({ clientId: 'client-ping', accountId: 'accountId', params: { client_notification_token: 'foo' } });
      nock('https://rp.example.com/')
        .post('/ping')
        .reply(200);
      await this.provider.backchannelResult(request, result);
    });

    it('pings the client (400)', async function () {
      const result = new this.provider.Grant({ clientId: 'client-ping', accountId: 'accountId' });
      const request = new this.provider.BackchannelAuthenticationRequest({ clientId: 'client-ping', accountId: 'accountId', params: { client_notification_token: 'foo' } });
      nock('https://rp.example.com/')
        .post('/ping')
        .reply(400);
      return assert.rejects(this.provider.backchannelResult(request, result), { name: 'Error', message: 'expected 204 No Content from https://rp.example.com/ping, got: 400 Bad Request' });
    });
  });

  describe('backchannel_authentication_endpoint', () => {
    const route = '/backchannel';

    describe('client validation', () => {
      it('only responds to clients with urn:openid:params:grant-type:ciba enabled', function () {
        const spy = sinon.spy();
        this.provider.once('backchannel_authentication.error', spy);

        return this.agent.post(route)
          .send({
            client_id: 'client-not-allowed',
          })
          .type('form')
          .expect(400)
          .expect('content-type', /application\/json/)
          .expect({
            error: 'unauthorized_client',
            error_description: 'urn:openid:params:grant-type:ciba is not allowed for this client',
          })
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
          });
      });

      it('rejects invalid clients', function () {
        const spy = sinon.spy();
        this.provider.once('backchannel_authentication.error', spy);

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

    it('rejects other than application/x-www-form-urlencoded', function () {
      const spy = sinon.spy();
      this.provider.once('backchannel_authentication.error', spy);

      return this.agent.post(route)
        .send({
          client_id: 'client',
        })
        .expect(400)
        .expect('content-type', /application\/json/)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
        })
        .expect({
          error: 'invalid_request',
          error_description: 'only application/x-www-form-urlencoded content-type bodies are supported on POST /backchannel',
        });
    });

    describe('param validation', () => {
      it('requires the scope param', async function () {
        const spy = sinon.spy();
        this.provider.once('backchannel_authentication.error', spy);

        return this.agent.post(route)
          .send({
            client_id: 'client',
          })
          .type('form')
          .expect(400)
          .expect('content-type', /application\/json/)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
          })
          .expect({
            error: 'invalid_request',
            error_description: "missing required parameter 'scope'",
          });
      });

      it('requires the client_notification_token param when using ping', async function () {
        const spy = sinon.spy();
        this.provider.once('backchannel_authentication.error', spy);

        return this.agent.post(route)
          .send({
            client_id: 'client-ping',
            scope: 'openid',
          })
          .type('form')
          .expect(400)
          .expect('content-type', /application\/json/)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
          })
          .expect({
            error: 'invalid_request',
            error_description: "missing required parameter 'client_notification_token'",
          });
      });

      it('requires the scope param with openid', async function () {
        const spy = sinon.spy();
        this.provider.once('backchannel_authentication.error', spy);

        return this.agent.post(route)
          .send({
            client_id: 'client',
            scope: 'foo',
          })
          .type('form')
          .expect(400)
          .expect('content-type', /application\/json/)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
          })
          .expect({
            error: 'invalid_request',
            error_description: 'openid scope must be requested for this request',
          });
      });

      it('validates requested_expiry', async function () {
        const spy = sinon.spy();
        this.provider.once('backchannel_authentication.error', spy);

        return this.agent.post(route)
          .send({
            client_id: 'client',
            scope: 'openid',
            requested_expiry: 0,
          })
          .type('form')
          .expect(400)
          .expect('content-type', /application\/json/)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
          })
          .expect({
            error: 'invalid_request',
            error_description: 'invalid requested_expiry parameter value',
          });
      });

      it('validates one of the hints is provided', async function () {
        const spy = sinon.spy();
        this.provider.once('backchannel_authentication.error', spy);

        return this.agent.post(route)
          .send({
            client_id: 'client',
            scope: 'openid',
          })
          .type('form')
          .expect(400)
          .expect('content-type', /application\/json/)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
          })
          .expect({
            error: 'invalid_request',
            error_description: 'missing one of required parameters login_hint_token, id_token_hint, or login_hint',
          });
      });

      it('validates exactly one of the hints is provided', async function () {
        const spy = sinon.spy();
        this.provider.once('backchannel_authentication.error', spy);

        return this.agent.post(route)
          .send({
            client_id: 'client',
            scope: 'openid',
            login_hint_token: 'foo',
            login_hint: 'foo',
          })
          .type('form')
          .expect(400)
          .expect('content-type', /application\/json/)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
          })
          .expect({
            error: 'invalid_request',
            error_description: 'only one of required parameters login_hint_token, id_token_hint, or login_hint must be provided',
          });
      });

      it('validates request object is used', async function () {
        const spy = sinon.spy();
        this.provider.once('backchannel_authentication.error', spy);

        return this.agent.post(route)
          .send({
            client_id: 'client-signed',
            scope: 'openid',
          })
          .type('form')
          .expect(400)
          .expect('content-type', /application\/json/)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
          })
          .expect({
            error: 'invalid_request',
            error_description: 'Request Object must be used by this client',
          });
      });

      it('validates Encrypted Request Objects are not used', async function () {
        const spy = sinon.spy();
        this.provider.once('backchannel_authentication.error', spy);

        return this.agent.post(route)
          .send({
            client_id: 'client-signed',
            scope: 'openid',
            request: '....',
          })
          .type('form')
          .expect(400)
          .expect('content-type', /application\/json/)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
          })
          .expect({
            error: 'invalid_request',
            error_description: 'Encrypted Request Objects are not supported by CIBA',
          });
      });
    });
  });
});
