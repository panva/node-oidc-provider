const { parse: parseUrl } = require('url');

const sinon = require('sinon');
const { expect } = require('chai');
const snakeCase = require('lodash/snakeCase');

const bootstrap = require('../test_helper');

describe('requests without the openid scope', () => {
  before(bootstrap(__dirname));

  afterEach(function () {
    this.provider.removeAllListeners();
  });

  describe('openid scope gated parameters', () => {
    ['acr_values', 'claims', 'claims_locales', 'id_token_hint', 'max_age', 'nonce'].forEach((param) => {
      it(`${param} can only be used when openid is amongst the requested scopes`, async function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          [param]: 'foo',
        });

        await this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(302)
          .expect(auth.validatePresence(['error', 'error_description', 'state'])) // notice state is not expected
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription(`openid scope must be requested when using the ${param} parameter`));
      });
    });

    Object.entries({
      defaultAcrValues: ['foo'],
      defaultMaxAge: 300,
      requireAuthTime: true,
    }).forEach(([clientProperty, value]) => {
      it(`must be provided when client is configured with ${snakeCase(clientProperty)}`, async function () {
        const auth = new this.AuthorizationRequest({
          client_id: 'client',
          response_type: 'code',
        });

        const client = await this.provider.Client.find('client');

        client[clientProperty] = value;

        await this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(() => {
            delete client[clientProperty];
          })
          .expect(302)
          .expect(auth.validatePresence(['error', 'error_description', 'state'])) // notice state is not expected
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription(`openid scope must be requested for clients with ${snakeCase(clientProperty)}`));
      });
    });
  });

  describe('response_types and flows that work when scope parameter is missing openid scope', () => {
    const scope = 'api:read';
    describe('when scope is e.g. missing openid (api:read)', () => {
      before(function () { return this.login({ scope }); });
      after(function () { return this.logout(); });

      describe('response_type=code', () => {
        const response_type = 'code';
        it('gets a code from the authorization endpoint', async function () {
          const auth = new this.AuthorizationRequest({
            response_type,
            scope,
          });

          const spy = sinon.spy();
          this.provider.on('authorization_code.saved', spy);

          await this.wrap({ route: '/auth', verb: 'get', auth })
            .expect(302)
            .expect(auth.validateClientLocation)
            .expect(auth.validatePresence(['code', 'state']));

          expect(spy.calledOnce).to.be.true;
          expect(spy.args[0][0]).to.have.property('scope', scope);
        });

        describe('authorization code exchange', () => {
          beforeEach(async function () {
            const auth = new this.AuthorizationRequest({
              response_type,
              scope,
            });

            await this.wrap({ route: '/auth', verb: 'get', auth })
              .expect(302)
              .expect(auth.validateClientLocation)
              .expect(auth.validatePresence(['code', 'state']))
              .expect((response) => {
                const { query: { code } } = parseUrl(response.headers.location, true);
                this.code = code;
              });
          });

          it('gets an access token', async function () {
            const spy = sinon.spy();
            this.provider.on('access_token.saved', spy);

            await this.agent.post('/token')
              .send({
                client_id: 'client',
                grant_type: 'authorization_code',
                code: this.code,
              })
              .type('form')
              .expect(200)
              .expect(({ body }) => {
                expect(body).to.have.property('access_token');
                expect(body).not.to.have.property('id_token');
              });

            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][0]).to.have.property('scope', scope);
          });

          it('gets an access token and a refresh token', async function () {
            const adapter = this.TestAdapter.for('AuthorizationCode');
            const jti = this.getTokenJti(this.code);

            const refreshScope = `${scope || ''} offline_access`.trim();

            adapter.syncUpdate(jti, {
              scope: refreshScope,
            });
            this.getSession().authorizations.client.promptedScopes.push('offline_access');

            const spy = sinon.spy();
            this.provider.on('access_token.saved', spy);
            this.provider.on('refresh_token.saved', spy);

            await this.agent.post('/token')
              .send({
                client_id: 'client',
                grant_type: 'authorization_code',
                code: this.code,
              })
              .type('form')
              .expect(200)
              .expect(({ body }) => {
                expect(body).to.have.property('access_token');
                expect(body).to.have.property('refresh_token');
                expect(body).not.to.have.property('id_token');
              });

            expect(spy.calledTwice).to.be.true;
            expect(spy.args[0][0]).to.have.property('scope', refreshScope);
            expect(spy.args[1][0]).to.have.property('scope', refreshScope);
          });
        });

        describe('refresh token exchange', () => {
          const refreshScope = `${scope || ''} offline_access`.trim();

          beforeEach(async function () {
            const auth = new this.AuthorizationRequest({
              response_type,
              scope,
            });

            let code;
            await this.wrap({ route: '/auth', verb: 'get', auth })
              .expect(302)
              .expect(auth.validateClientLocation)
              .expect(auth.validatePresence(['code', 'state']))
              .expect((response) => {
                ({ query: { code } } = parseUrl(response.headers.location, true));
              });

            const adapter = this.TestAdapter.for('AuthorizationCode');
            const jti = this.getTokenJti(code);

            adapter.syncUpdate(jti, {
              scope: refreshScope,
            });
            this.getSession().authorizations.client.promptedScopes.push('offline_access');

            await this.agent.post('/token')
              .send({
                client_id: 'client',
                grant_type: 'authorization_code',
                code,
              })
              .type('form')
              .expect(200)
              .expect(({ body }) => {
                this.rt = body.refresh_token;
              });
          });

          it('gets an access token and a refresh token', async function () {
            const spy = sinon.spy();
            this.provider.on('access_token.saved', spy);
            this.provider.on('refresh_token.saved', spy);

            await this.agent.post('/token')
              .send({
                client_id: 'client',
                grant_type: 'refresh_token',
                refresh_token: this.rt,
              })
              .type('form')
              .expect(200)
              .expect(({ body }) => {
                expect(body).to.have.property('access_token');
                expect(body).to.have.property('refresh_token');
                expect(body).not.to.have.property('id_token');
              });

            expect(spy.calledTwice).to.be.true;
            expect(spy.args[0][0]).to.have.property('scope', refreshScope);
            expect(spy.args[1][0]).to.have.property('scope', refreshScope);
          });
        });
      });

      describe('response_type=token', () => {
        const response_type = 'token';

        it('gets a token from the authorization endpoint', async function () {
          const auth = new this.AuthorizationRequest({
            response_type,
            scope,
          });

          const spy = sinon.spy();
          this.provider.on('access_token.saved', spy);

          await this.wrap({ route: '/auth', verb: 'get', auth })
            .expect(302)
            .expect(auth.validateFragment)
            .expect(auth.validateClientLocation)
            .expect(auth.validatePresence(['access_token', 'state', 'expires_in', 'token_type', 'scope']));

          expect(spy.calledOnce).to.be.true;
          expect(spy.args[0][0]).to.have.property('scope', scope);
        });
      });

      describe('response_type=none', () => {
        const response_type = 'none';

        it('gets nothing from the authorization endpoint', async function () {
          const auth = new this.AuthorizationRequest({
            response_type,
            scope,
          });

          const spy = sinon.spy();
          this.provider.on('authorization.success', spy);

          await this.wrap({ route: '/auth', verb: 'get', auth })
            .expect(302)
            .expect(auth.validateClientLocation)
            .expect(auth.validatePresence(['state']));

          expect(spy.calledOnce).to.be.true;
          expect(spy.args[0][0].oidc.params).to.have.deep.property('scope', scope);
        });
      });
    });

    describe('device flow', () => {
      it('accepts the device authorization request', async function () {
        const spy = sinon.spy();
        this.provider.on('device_code.saved', spy);

        await this.agent.post('/device/auth')
          .send({
            client_id: 'client',
            scope,
          })
          .type('form')
          .expect(200);

        expect(spy.calledOnce).to.be.true;
        if (scope) {
          expect(spy.args[0][0]).to.have.nested.property('params.scope', scope);
        } else {
          expect(spy.args[0][0]).not.to.have.nested.property('params.scope');
        }
      });

      describe('urn:ietf:params:oauth:grant-type:device_code', () => {
        beforeEach(async function () {
          this.provider.on('device_code.saved', (token) => {
            this.jti = token.jti;
          });

          await this.agent.post('/device/auth')
            .send({
              client_id: 'client',
              scope,
            })
            .type('form')
            .expect(200)
            .expect(({ body }) => {
              this.code = body.device_code;
            });

          this.TestAdapter.for('DeviceCode').syncUpdate(this.jti, {
            scope,
            accountId: 'sub',
            clientId: 'client',
          });
        });

        it('gets an access token', async function () {
          const spy = sinon.spy();
          this.provider.on('access_token.saved', spy);

          await this.agent.post('/token')
            .send({
              client_id: 'client',
              grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
              device_code: this.code,
            })
            .type('form')
            .expect(200)
            .expect(({ body }) => {
              expect(body).to.have.property('access_token');
              expect(body).not.to.have.property('id_token');
            });

          expect(spy.calledOnce).to.be.true;
          expect(spy.args[0][0]).to.have.property('scope', scope);
        });

        it('gets an access and a refresh_token', async function () {
          const refreshScope = `${scope || ''} offline_access`.trim();
          const spy = sinon.spy();
          this.provider.on('access_token.saved', spy);
          this.provider.on('refresh_token.saved', spy);

          this.TestAdapter.for('DeviceCode').syncUpdate(this.jti, {
            scope: refreshScope,
          });

          await this.agent.post('/token')
            .send({
              client_id: 'client',
              grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
              device_code: this.code,
            })
            .type('form')
            .expect(200)
            .expect(({ body }) => {
              expect(body).to.have.property('access_token');
              expect(body).to.have.property('refresh_token');
              expect(body).not.to.have.property('id_token');
            });

          expect(spy.calledTwice).to.be.true;
          expect(spy.args[0][0]).to.have.property('scope', refreshScope);
          expect(spy.args[1][0]).to.have.property('scope', refreshScope);
        });
      });
    });
  });

  describe('response_types that require openid scope', () => {
    ['code id_token token', 'code id_token', 'id_token token', 'id_token'].forEach((response_type) => {
      it(`scope must be present when requesting ${response_type}`, async function () {
        const auth = new this.AuthorizationRequest({
          response_type,
        });

        delete auth.scope;
        delete auth.state;

        await this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description'])) // notice state is not expected
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('openid scope must be requested for this response_type'));
      });

      it(`openid scope value must be present when requesting ${response_type}`, async function () {
        const auth = new this.AuthorizationRequest({
          response_type,
          scope: 'api:read',
        });

        delete auth.state;

        await this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description'])) // notice state is not expected
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('openid scope must be requested for this response_type'));
      });
    });
  });
});
