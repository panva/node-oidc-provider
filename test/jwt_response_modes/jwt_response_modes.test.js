const url = require('url');

const { expect } = require('chai');
const sinon = require('sinon');

const bootstrap = require('../test_helper');
const { decode } = require('../../lib/helpers/jwt');

const route = '/auth';

describe('configuration features.jwtResponseModes', () => {
  before(bootstrap(__dirname));

  describe('discovery', () => {
    it('extends the well known config', function () {
      return this.agent.get('/.well-known/openid-configuration')
        .expect((response) => {
          expect(response.body).to.have.property('authorization_signing_alg_values_supported');
          expect(response.body).to.have.property('authorization_encryption_alg_values_supported');
          expect(response.body).to.have.property('authorization_encryption_enc_values_supported');
          expect(response.body.response_modes_supported).to.include('jwt');
          expect(response.body.response_modes_supported).to.include('query.jwt');
          expect(response.body.response_modes_supported).to.include('fragment.jwt');
          expect(response.body.response_modes_supported).to.include('form_post.jwt');
          expect(response.body.response_modes_supported).to.include('web_message.jwt');
        });
    });
  });

  describe('response_mode=jwt', () => {
    before(function () { return this.login(); });
    after(function () { return this.logout(); });

    it('defaults to fragment for implicit and hybrid response types', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'id_token token',
        response_mode: 'jwt',
        scope: 'openid',
      });

      await this.wrap({ route, auth, verb: 'get' })
        .expect(302)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['response']))
        .expect(auth.validateClientLocation)
        .expect(({ headers: { location } }) => {
          const { query: { response } } = url.parse(location, true);
          const { payload } = decode(response);
          expect(payload).to.include.keys('id_token', 'access_token', 'expires_in', 'token_type');
          expect(payload).to.have.property('exp').that.is.a('number');
          expect(payload).to.have.property('aud', 'client');
          expect(payload).to.have.property('scope', 'openid');
          expect(payload).to.have.property('state', auth.state);
          expect(payload).to.have.property('iss', this.provider.issuer);
        });
    });

    it('defaults to query for code response type', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        response_mode: 'jwt',
        scope: 'openid',
      });

      await this.wrap({ route, auth, verb: 'get' })
        .expect(302)
        .expect(auth.validatePresence(['response']))
        .expect(auth.validateClientLocation)
        .expect(({ headers: { location } }) => {
          const { query: { response } } = url.parse(location, true);
          const { payload } = decode(response);
          expect(payload).to.include.keys('code');
          expect(payload).to.have.property('exp').that.is.a('number');
          expect(payload).to.have.property('aud', 'client');
          expect(payload).not.to.have.property('scope');
          expect(payload).to.have.property('state', auth.state);
          expect(payload).to.have.property('iss', this.provider.issuer);
        });
    });

    it('defaults to query for none response type', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'none',
        response_mode: 'jwt',
        scope: 'openid',
      });

      await this.wrap({ route, auth, verb: 'get' })
        .expect(302)
        .expect(auth.validatePresence(['response']))
        .expect(auth.validateClientLocation)
        .expect(({ headers: { location } }) => {
          const { query: { response } } = url.parse(location, true);
          const { payload } = decode(response);
          expect(payload).to.have.all.keys('exp', 'aud', 'state', 'iss');
        });
    });

    describe('when secret is expired', () => {
      it('defaults to fragment for implicit and hybrid response types', async function () {
        const auth = new this.AuthorizationRequest({
          client_id: 'client-expired',
          response_type: 'id_token token',
          response_mode: 'jwt',
          scope: 'openid',
        });

        await this.wrap({ route, auth, verb: 'get' })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_client'))
          .expect(auth.validateErrorDescription('client secret is expired, cannot issue a JWT Authorization response'));
      });

      it('defaults to query for code response type', async function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          response_mode: 'jwt',
          scope: 'openid',
          client_id: 'client-expired',
        });

        await this.wrap({ route, auth, verb: 'get' })
          .expect(302)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_client'))
          .expect(auth.validateErrorDescription('client secret is expired, cannot issue a JWT Authorization response'));
      });

      it('defaults to query for none response type', async function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'none',
          response_mode: 'jwt',
          scope: 'openid',
          client_id: 'client-expired',
        });

        await this.wrap({ route, auth, verb: 'get' })
          .expect(302)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_client'))
          .expect(auth.validateErrorDescription('client secret is expired, cannot issue a JWT Authorization response'));
      });
    });
  });

  describe('response_mode=query.jwt', () => {
    before(function () { return this.login(); });
    after(function () { return this.logout(); });

    it('is forbidden for implicit and hybrid response types unless encrypted', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'id_token token',
        response_mode: 'query.jwt',
        scope: 'openid',
      });

      await this.wrap({ route, auth, verb: 'get' })
        .expect(302)
        .expect(auth.validatePresence(['response']))
        .expect(auth.validateClientLocation)
        .expect(({ headers: { location } }) => {
          const { query: { response } } = url.parse(location, true);
          const { payload } = decode(response);
          expect(payload).to.have.all.keys('error', 'error_description', 'state', 'aud', 'exp', 'iss');
          expect(payload.error).to.eql('invalid_request');
          expect(payload.error_description).to.eql('response_mode not allowed for this response_type unless encrypted');
        });
    });

    it('uses the query part when expired', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'id_token token',
        response_mode: 'query.jwt',
        scope: 'openid',
        client_id: 'client-expired',
      });

      await this.wrap({ route, auth, verb: 'get' })
        .expect(302)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_client'))
        .expect(auth.validateErrorDescription('client secret is expired, cannot issue a JWT Authorization response'));
    });

    it('is allowed for implicit and hybrid response types if encrypted', async function () {
      const spy = sinon.spy();
      this.provider.once('authorization.success', spy);
      const auth = new this.AuthorizationRequest({
        client_id: 'client-encrypted',
        response_type: 'id_token token',
        response_mode: 'query.jwt',
        scope: 'openid',
      });

      await this.wrap({ route, auth, verb: 'get' })
        .expect(302)
        .expect(auth.validatePresence(['response']))
        .expect(auth.validateClientLocation);

      expect(spy).to.have.property('calledOnce', true);
    });

    it('is allowed for code response type', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        response_mode: 'query.jwt',
        scope: 'openid',
      });

      await this.wrap({ route, auth, verb: 'get' })
        .expect(302)
        .expect(auth.validatePresence(['response']))
        .expect(auth.validateClientLocation)
        .expect(({ headers: { location } }) => {
          const { query: { response } } = url.parse(location, true);
          const { payload } = decode(response);
          expect(payload).to.include.keys('code');
          expect(payload).to.have.property('exp').that.is.a('number');
          expect(payload).to.have.property('aud', 'client');
          expect(payload).not.to.have.property('scope');
          expect(payload).to.have.property('state', auth.state);
          expect(payload).to.have.property('iss', this.provider.issuer);
        });
    });

    it('is allowed for none response type', async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'none',
        response_mode: 'query.jwt',
        scope: 'openid',
      });

      await this.wrap({ route, auth, verb: 'get' })
        .expect(302)
        .expect(auth.validatePresence(['response']))
        .expect(auth.validateClientLocation)
        .expect(({ headers: { location } }) => {
          const { query: { response } } = url.parse(location, true);
          const { payload } = decode(response);
          expect(payload).to.have.all.keys('exp', 'aud', 'state', 'iss');
        });
    });
  });

  Object.entries({
    'query.jwt': [302, 302],
    'fragment.jwt': [302, 302],
    'form_post.jwt': [400, 500],
    'web_message.jwt': [400, 500],
  }).forEach(([mode, [errStatus, exceptionStatus]]) => {
    context(`${mode} err handling`, () => {
      it(`responds with a ${errStatus}`, function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          prompt: 'none',
          response_mode: mode,
          scope: 'openid',
        });

        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);

        return this.wrap({ route, verb: 'get', auth })
          .expect(errStatus)
          .expect(() => {
            expect(spy.called).to.be.true;
          });
      });

      it('handles expired secrets', async function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);

        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          response_mode: mode,
          scope: 'openid',
          client_id: 'client-expired',
        });

        await this.wrap({ route, auth, verb: 'get' })
          .expect(errStatus)
          .expect(() => {
            expect(spy.called).to.be.true;
            expect(spy.args[0][1]).to.have.property('error', 'invalid_client');
            expect(spy.args[0][1]).to.have.property('error_description', 'client secret is expired, cannot issue a JWT Authorization response');
          });
      });

      context('[exception]', () => {
        before(async function () {
          sinon.stub(this.provider.Session.prototype, 'accountId').throws();
        });

        after(async function () {
          this.provider.Session.prototype.accountId.restore();
        });

        it(`responds with a ${exceptionStatus}`, function () {
          const auth = new this.AuthorizationRequest({
            response_type: 'code',
            prompt: 'none',
            response_mode: mode,
            scope: 'openid',
          });

          const spy = sinon.spy();
          this.provider.once('server_error', spy);

          return this.wrap({ route, verb: 'get', auth })
            .expect(exceptionStatus)
            .expect(() => {
              expect(spy.called).to.be.true;
            });
        });
      });
    });
  });
});
