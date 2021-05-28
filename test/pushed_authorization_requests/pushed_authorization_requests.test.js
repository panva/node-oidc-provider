const { expect } = require('chai');
const sinon = require('sinon');
const jose = require('jose2');
const { parseJwk } = require('jose/jwk/parse'); // eslint-disable-line import/no-unresolved

const JWT = require('../../lib/helpers/jwt');
const bootstrap = require('../test_helper');

describe('Pushed Request Object', () => {
  before(bootstrap(__dirname));

  before(async function () {
    const client = await this.provider.Client.find('client');
    this.key = await parseJwk(client.symmetricKeyStore.selectForSign({ alg: 'HS256' })[0]);
  });

  describe('discovery', () => {
    it('extends the well known config', async function () {
      await this.agent.get('/.well-known/openid-configuration')
        .expect((response) => {
          expect(response.body).not.to.have.property('request_object_endpoint');
          expect(response.body).to.have.property('pushed_authorization_request_endpoint');
          expect(response.body).to.have.deep.property('request_object_signing_alg_values_supported').with.not.lengthOf(0);
          expect(response.body).to.have.property('request_parameter_supported', false);
          expect(response.body).to.have.property('request_uri_parameter_supported', false);
          expect(response.body).not.to.have.property('require_pushed_authorization_requests');
        });

      i(this.provider).configuration('features.pushedAuthorizationRequests').requirePushedAuthorizationRequests = true;

      return this.agent.get('/.well-known/openid-configuration')
        .expect((response) => {
          expect(response.body).to.have.property('require_pushed_authorization_requests', true);
        });
    });

    after(function () {
      i(this.provider).configuration('features.pushedAuthorizationRequests').requirePushedAuthorizationRequests = false;
    });
  });

  ['client', 'client-par-required'].forEach((clientId) => {
    const requirePushedAuthorizationRequests = clientId === 'client-par-required';

    describe(`when require_pushed_authorization_requests=${requirePushedAuthorizationRequests}`, () => {
      describe('using a JAR request parameter', () => {
        describe('Pushed Authorization Request Endpoint', () => {
          it('populates ctx.oidc.entities', function (done) {
            this.provider.use(this.assertOnce((ctx) => {
              expect(ctx.oidc.entities).to.have.keys('Client', 'PushedAuthorizationRequest');
            }, done));

            JWT.sign({
              response_type: 'code',
              client_id: clientId,
              iss: clientId,
              aud: this.provider.issuer,
            }, this.key, 'HS256').then((request) => {
              this.agent.post('/request')
                .auth(clientId, 'secret')
                .type('form')
                .send({ request })
                .end(() => {});
            });
          });

          it('stores a request object and returns a uri', async function () {
            const spy = sinon.spy();
            this.provider.once('pushed_authorization_request.success', spy);

            await this.agent.post('/request')
              .auth(clientId, 'secret')
              .type('form')
              .send({
                request: await JWT.sign({
                  response_type: 'code',
                  client_id: clientId,
                  iss: clientId,
                  aud: this.provider.issuer,
                }, this.key, 'HS256'),
              })
              .expect(201)
              .expect(({ body }) => {
                expect(body).to.have.keys('expires_in', 'request_uri');
                expect(body).to.have.property('expires_in', 60);
                expect(body).to.have.property('request_uri').and.match(/^urn:ietf:params:oauth:request_uri:(.+)$/);
              });

            expect(spy).to.have.property('calledOnce', true);
          });

          it('uses the expiration from JWT when below MAX_TTL', async function () {
            const spy = sinon.spy();
            this.provider.once('pushed_authorization_request.success', spy);

            await this.agent.post('/request')
              .auth(clientId, 'secret')
              .type('form')
              .send({
                request: await JWT.sign({
                  response_type: 'code',
                  client_id: clientId,
                  iss: clientId,
                  aud: this.provider.issuer,
                }, this.key, 'HS256', {
                  expiresIn: 20,
                }),
              })
              .expect(201)
              .expect(({ body }) => {
                expect(body).to.have.keys('expires_in', 'request_uri');
                expect(body).to.have.property('expires_in').to.be.closeTo(20, 1);
                expect(body).to.have.property('request_uri').and.match(/^urn:ietf:params:oauth:request_uri:(.+)$/);
              });

            expect(spy).to.have.property('calledOnce', true);
          });

          it('uses MAX_TTL when the expiration from JWT is above it', async function () {
            const spy = sinon.spy();
            this.provider.once('pushed_authorization_request.success', spy);

            await this.agent.post('/request')
              .auth(clientId, 'secret')
              .type('form')
              .send({
                request: await JWT.sign({
                  response_type: 'code',
                  client_id: clientId,
                  iss: clientId,
                  aud: this.provider.issuer,
                }, this.key, 'HS256', {
                  expiresIn: 120,
                }),
              })
              .expect(201)
              .expect(({ body }) => {
                expect(body).to.have.keys('expires_in', 'request_uri');
                expect(body).to.have.property('expires_in', 60);
                expect(body).to.have.property('request_uri').and.match(/^urn:ietf:params:oauth:request_uri:(.+)$/);
              });

            expect(spy).to.have.property('calledOnce', true);
          });

          it('ignores regular parameters when passing a JAR request', async function () {
            const spy = sinon.spy();
            this.provider.once('pushed_authorization_request.saved', spy);

            await this.agent.post('/request')
              .auth(clientId, 'secret')
              .type('form')
              .send({
                nonce: 'foo',
                response_type: 'code token',
                request: await JWT.sign({
                  response_type: 'code',
                  client_id: clientId,
                  iss: clientId,
                  aud: this.provider.issuer,
                }, this.key, 'HS256'),
              })
              .expect(201);

            expect(spy).to.have.property('calledOnce', true);
            const { request } = spy.args[0][0];
            const payload = jose.JWT.decode(request);
            expect(payload).not.to.have.property('nonce');
            expect(payload).to.have.property('response_type', 'code');
          });

          it('requires the registered request object signing alg be used', async function () {
            return this.agent.post('/request')
              .auth('client-alg-registered', 'secret')
              .type('form')
              .send({
                request: await JWT.sign({
                  response_type: 'code',
                  client_id: 'client-alg-registered',
                }, undefined, 'none'),
              })
              .expect(400)
              .expect({
                error: 'invalid_request_object',
                error_description: 'the preregistered alg must be used in request or request_uri',
              });
          });

          it('requires the request object client_id to equal the authenticated client one', async function () {
            return this.agent.post('/request')
              .auth(clientId, 'secret')
              .type('form')
              .send({
                request: await JWT.sign({
                  response_type: 'code',
                  client_id: 'client-foo',
                }, this.key, 'HS256'),
              })
              .expect(400)
              .expect({
                error: 'invalid_request_object',
                error_description: "request client_id must equal the authenticated client's client_id",
              });
          });

          it('remaps request validation errors to be related to the request object', async function () {
            return this.agent.post('/request')
              .auth(clientId, 'secret')
              .type('form')
              .send({
                request: await JWT.sign({
                  response_type: 'code',
                  client_id: clientId,
                  iss: clientId,
                  aud: this.provider.issuer,
                  redirect_uri: 'https://rp.example.com/unlisted',
                }, this.key, 'HS256'),
              })
              .expect(400)
              .expect({
                error: 'invalid_request',
                error_description: "redirect_uri did not match any of the client's registered redirect_uris",
              });
          });

          it('leaves non OIDCProviderError alone', async function () {
            const adapterThrow = new Error('adapter throw!');
            sinon.stub(this.TestAdapter.for('PushedAuthorizationRequest'), 'upsert').callsFake(async () => { throw adapterThrow; });
            return this.agent.post('/request')
              .auth(clientId, 'secret')
              .type('form')
              .send({
                request: await JWT.sign({
                  response_type: 'code',
                  client_id: clientId,
                  iss: clientId,
                  aud: this.provider.issuer,
                }, this.key, 'HS256'),
              })
              .expect(() => {
                this.TestAdapter.for('PushedAuthorizationRequest').upsert.restore();
              })
              .expect(500)
              .expect({
                error: 'server_error',
                error_description: 'oops! something went wrong',
              });
          });
        });

        describe('Using Pushed Authorization Requests', () => {
          before(function () { return this.login(); });
          after(function () { return this.logout(); });

          it('allows the request_uri to be used', async function () {
            const { body: { request_uri } } = await this.agent.post('/request')
              .auth(clientId, 'secret')
              .type('form')
              .send({
                request: await JWT.sign({
                  scope: 'openid',
                  response_type: 'code',
                  client_id: clientId,
                  iss: clientId,
                  aud: this.provider.issuer,
                }, this.key, 'HS256'),
              });

            let id = request_uri.split(':');
            id = id[id.length - 1];

            expect(await this.provider.PushedAuthorizationRequest.find(id)).to.be.ok;

            const auth = new this.AuthorizationRequest({
              client_id: clientId,
              iss: clientId,
              aud: this.provider.issuer,
              state: undefined,
              redirect_uri: undefined,
              request_uri,
            });

            await this.wrap({ route: '/auth', verb: 'get', auth })
              .expect(303)
              .expect(auth.validatePresence(['code']));

            expect(await this.provider.PushedAuthorizationRequest.find(id)).not.to.be.ok;
          });

          it('handles expired or invalid pushed authorization request object', async function () {
            const auth = new this.AuthorizationRequest({
              request_uri: 'urn:ietf:params:oauth:request_uri:foobar',
            });

            return this.wrap({ route: '/auth', verb: 'get', auth })
              .expect(303)
              .expect(auth.validatePresence(['error', 'error_description', 'state']))
              .expect(auth.validateState)
              .expect(auth.validateClientLocation)
              .expect(auth.validateError('invalid_request_uri'))
              .expect(auth.validateErrorDescription('request_uri is invalid or expired'));
          });

          it('handles expired or invalid pushed authorization request object (when no client_id in the request)', async function () {
            const renderSpy = sinon.spy(i(this.provider).configuration(), 'renderError');

            const auth = new this.AuthorizationRequest({
              client_id: undefined,
              request_uri: 'urn:ietf:params:oauth:request_uri:foobar',
            });

            return this.wrap({ route: '/auth', verb: 'get', auth })
              .expect(() => {
                renderSpy.restore();
              })
              .expect(400)
              .expect(() => {
                expect(renderSpy.calledOnce).to.be.true;
                const renderArgs = renderSpy.args[0];
                expect(renderArgs[1]).to.have.property('error', 'invalid_request_uri');
                expect(renderArgs[1]).to.have.property('error_description', 'request_uri is invalid or expired');
              });
          });

          it('allows the request_uri to be used without passing client_id to the request', async function () {
            const { body: { request_uri } } = await this.agent.post('/request')
              .auth(clientId, 'secret')
              .type('form')
              .send({
                request: await JWT.sign({
                  scope: 'openid',
                  response_type: 'code',
                  client_id: clientId,
                  iss: clientId,
                  aud: this.provider.issuer,
                }, this.key, 'HS256'),
              });

            const auth = new this.AuthorizationRequest({
              client_id: undefined,
              state: undefined,
              redirect_uri: undefined,
              request_uri,
            });

            return this.wrap({ route: '/auth', verb: 'get', auth })
              .expect(303)
              .expect(auth.validatePresence(['code']));
          });
        });
      });

      describe('using a plain pushed authorization request', () => {
        describe('Pushed Authorization Request Endpoint', () => {
          it('populates ctx.oidc.entities', function (done) {
            this.provider.use(this.assertOnce((ctx) => {
              expect(ctx.oidc.entities).to.have.keys('Client', 'PushedAuthorizationRequest');
            }, done));

            this.agent.post('/request')
              .auth(clientId, 'secret')
              .type('form')
              .send({
                response_type: 'code',
                client_id: clientId,
                iss: clientId,
                aud: this.provider.issuer,
              })
              .end(() => {});
          });

          it('stores a request object and returns a uri', async function () {
            const spy = sinon.spy();
            this.provider.once('pushed_authorization_request.success', spy);

            await this.agent.post('/request')
              .auth(clientId, 'secret')
              .type('form')
              .send({
                response_type: 'code',
                client_id: clientId,
                iss: clientId,
                aud: this.provider.issuer,
              })
              .expect(201)
              .expect(({ body }) => {
                expect(body).to.have.keys('expires_in', 'request_uri');
                expect(body).to.have.property('expires_in', 60);
                expect(body).to.have.property('request_uri').and.match(/^urn:ietf:params:oauth:request_uri:(.+)$/);
              });

            expect(spy).to.have.property('calledOnce', true);
          });

          it('forbids request_uri to be used', async function () {
            return this.agent.post('/request')
              .auth(clientId, 'secret')
              .type('form')
              .send({
                response_type: 'code',
                request_uri: 'https://rp.example.com/jar#foo',
              })
              .expect(400)
              .expect({
                error: 'invalid_request',
                error_description: '`request_uri` parameter must not be used at the pushed_authorization_request_endpoint',
              });
          });

          it('does not remap request validation errors to be related to the request object', async function () {
            return this.agent.post('/request')
              .auth(clientId, 'secret')
              .type('form')
              .send({
                response_type: 'code',
                client_id: clientId,
                iss: clientId,
                aud: this.provider.issuer,
                redirect_uri: 'https://rp.example.com/unlisted',
              })
              .expect(400)
              .expect({
                error: 'invalid_request',
                error_description: "redirect_uri did not match any of the client's registered redirect_uris",
              });
          });

          it('leaves non OIDCProviderError alone', async function () {
            const adapterThrow = new Error('adapter throw!');
            sinon.stub(this.TestAdapter.for('PushedAuthorizationRequest'), 'upsert').callsFake(async () => { throw adapterThrow; });
            return this.agent.post('/request')
              .auth(clientId, 'secret')
              .type('form')
              .send({
                response_type: 'code',
                client_id: clientId,
                iss: clientId,
                aud: this.provider.issuer,
              })
              .expect(() => {
                this.TestAdapter.for('PushedAuthorizationRequest').upsert.restore();
              })
              .expect(500)
              .expect({
                error: 'server_error',
                error_description: 'oops! something went wrong',
              });
          });
        });

        describe('Using Pushed Authorization Requests', () => {
          before(function () { return this.login(); });
          after(function () { return this.logout(); });

          it('allows the request_uri to be used', async function () {
            const { body: { request_uri } } = await this.agent.post('/request')
              .auth(clientId, 'secret')
              .type('form')
              .send({
                scope: 'openid',
                response_type: 'code',
                client_id: clientId,
                iss: clientId,
                aud: this.provider.issuer,
              });

            let id = request_uri.split(':');
            id = id[id.length - 1];

            expect(await this.provider.PushedAuthorizationRequest.find(id)).to.be.ok;

            const auth = new this.AuthorizationRequest({
              client_id: clientId,
              iss: clientId,
              aud: this.provider.issuer,
              state: undefined,
              redirect_uri: undefined,
              request_uri,
            });

            await this.wrap({ route: '/auth', verb: 'get', auth })
              .expect(303)
              .expect(auth.validatePresence(['code']));

            expect(await this.provider.PushedAuthorizationRequest.find(id)).not.to.be.ok;
          });

          it('allows the request_uri to be used without passing client_id to the request', async function () {
            const { body: { request_uri } } = await this.agent.post('/request')
              .auth(clientId, 'secret')
              .type('form')
              .send({
                scope: 'openid',
                response_type: 'code',
                client_id: clientId,
                iss: clientId,
                aud: this.provider.issuer,
              });

            const auth = new this.AuthorizationRequest({
              client_id: undefined,
              state: undefined,
              redirect_uri: undefined,
              request_uri,
            });

            return this.wrap({ route: '/auth', verb: 'get', auth })
              .expect(303)
              .expect(auth.validatePresence(['code']));
          });
        });
      });
    });
  });
});
