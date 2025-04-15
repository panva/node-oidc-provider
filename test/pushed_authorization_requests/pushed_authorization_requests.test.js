import { randomBytes } from 'node:crypto';
import { parse as parseUrl } from 'node:url';

import { expect } from 'chai';
import sinon from 'sinon';
import { importJWK, decodeProtectedHeader, decodeJwt } from 'jose';

import * as JWT from '../../lib/helpers/jwt.js';
import bootstrap from '../test_helper.js';

describe('Pushed Request Object', () => {
  context('w/o Request Objects', () => {
    before(bootstrap(import.meta.url));

    describe('discovery', () => {
      it('extends the well known config', async function () {
        await this.agent.get('/.well-known/openid-configuration')
          .expect((response) => {
            expect(response.body).not.to.have.property('request_object_endpoint');
            expect(response.body).to.have.property('pushed_authorization_request_endpoint');
            expect(response.body).not.to.have.property('request_object_signing_alg_values_supported');
            expect(response.body).to.have.property('request_uri_parameter_supported', false);
            expect(response.body).not.to.have.property('require_pushed_authorization_requests');
          });

        i(this.provider).features.pushedAuthorizationRequests
          .requirePushedAuthorizationRequests = true;

        return this.agent.get('/.well-known/openid-configuration')
          .expect((response) => {
            expect(response.body).to.have.property('require_pushed_authorization_requests', true);
          });
      });

      after(function () {
        i(this.provider).features.pushedAuthorizationRequests
          .requirePushedAuthorizationRequests = false;
      });
    });

    ['client', 'client-par-required'].forEach((clientId) => {
      const requirePushedAuthorizationRequests = clientId === 'client-par-required';

      context('allowUnregisteredRedirectUris', () => {
        before(function () {
          i(this.provider).features.pushedAuthorizationRequests
            .allowUnregisteredRedirectUris = true;
        });
        after(function () {
          i(this.provider).features.pushedAuthorizationRequests
            .allowUnregisteredRedirectUris = false;
        });
        before(function () { return this.login(); });
        after(function () { return this.logout(); });

        it('allows unregistered redirect_uris to be used', async function () {
          const { body: { request_uri } } = await this.agent.post('/request')
            .auth(clientId, 'secret')
            .type('form')
            .send({
              scope: 'openid',
              response_type: 'code',
              client_id: clientId,
              iss: clientId,
              aud: this.provider.issuer,
              redirect_uri: 'https://rp.example.com/unlisted',
            })
            .expect(201);

          let id = request_uri.split(':');
          id = id[id.length - 1];

          const { request } = await this.provider.PushedAuthorizationRequest.find(id);
          expect(decodeJwt(request)).to.have.property('redirect_uri', 'https://rp.example.com/unlisted');

          const auth = new this.AuthorizationRequest({
            client_id: clientId,
            iss: clientId,
            aud: this.provider.issuer,
            state: undefined,
            redirect_uri: undefined,
            request_uri,
          });

          let code;
          await this.wrap({ route: '/auth', verb: 'get', auth })
            .expect(303)
            .expect(auth.validatePresence(['code']))
            .expect((response) => {
              ({ query: { code } } = parseUrl(response.headers.location, true));
              const jti = this.getTokenJti(code);
              expect(this.TestAdapter.for('AuthorizationCode').syncFind(jti)).to.have.property('redirectUri', 'https://rp.example.com/unlisted');
            });

          return this.agent.post('/token')
            .auth(clientId, 'secret')
            .type('form')
            .send({
              code,
              grant_type: 'authorization_code',
              redirect_uri: 'https://rp.example.com/unlisted',
            })
            .expect(200);
        });

        it('except for public clients', async function () {
          const testClientId = 'client-unregistered-test-public';
          return this.agent.post('/request')
            .type('form')
            .send({
              response_type: 'code',
              client_id: testClientId,
              iss: testClientId,
              aud: this.provider.issuer,
              redirect_uri: 'https://rp.example.com/unlisted',
            })
            .expect(400)
            .expect({
              error: 'invalid_request',
              error_description: "redirect_uri did not match any of the client's registered redirect_uris",
            });
        });

        it('still validates the URI to be valid redirect_uri', async function () {
          // must only contain valid uris
          await this.agent.post('/request')
            .auth(clientId, 'secret')
            .type('form')
            .send({
              scope: 'openid',
              response_type: 'code',
              client_id: clientId,
              iss: clientId,
              aud: this.provider.issuer,
              redirect_uri: 'not-a-valid-uri',
            })
            .expect(400)
            .expect({
              error: 'invalid_request',
              error_description: 'redirect_uri must only contain valid uris',
            });

          // must not contain fragments
          await this.agent.post('/request')
            .auth(clientId, 'secret')
            .type('form')
            .send({
              scope: 'openid',
              response_type: 'code',
              client_id: clientId,
              iss: clientId,
              aud: this.provider.issuer,
              redirect_uri: 'https://rp.example.com/unlisted#fragment',
            })
            .expect(400)
            .expect({
              error: 'invalid_request',
              error_description: 'redirect_uri must not contain fragments',
            });
        });
      });

      describe(`when require_pushed_authorization_requests=${requirePushedAuthorizationRequests}`, () => {
        describe('using a JAR request parameter', () => {
          it('is not enabled', async function () {
            return this.agent.post('/request')
              .auth(clientId, 'secret')
              .type('form')
              .send({
                client_id: clientId,
                request: 'this.should.be.a.jwt',
              })
              .expect(400)
              .expect({
                error: 'request_not_supported',
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
              const spy2 = sinon.spy();
              this.provider.once('pushed_authorization_request.saved', spy2);

              await this.agent.post('/request')
                .auth(clientId, 'secret')
                .type('form')
                .send({
                  scope: 'openid',
                  response_type: 'code',
                  client_id: clientId,
                  iss: clientId,
                  extra: 'provided',
                  aud: this.provider.issuer,
                  claims: JSON.stringify({
                    id_token: {
                      auth_time: { essential: true },
                    },
                  }),
                })
                .expect(201)
                .expect(({ body }) => {
                  expect(body).to.have.keys('expires_in', 'request_uri');
                  expect(body).to.have.property('expires_in').closeTo(60, 1);
                  expect(body).to.have.property('request_uri').and.match(/^urn:ietf:params:oauth:request_uri:(.+)$/);
                });

              expect(spy).to.have.property('calledOnce', true);
              expect(spy.args[0][0].oidc.params).to.include({
                extra: 'provided',
                extra2: 'defaulted',
              });
              expect(spy2).to.have.property('calledOnce', true);
              const stored = spy2.args[0][0];
              expect(stored).to.have.property('trusted', true);
              const header = decodeProtectedHeader(stored.request);
              expect(header).to.deep.eql({ alg: 'none' });
              const payload = decodeJwt(stored.request);
              expect(payload).to.contain.keys(['aud', 'exp', 'iat', 'nbf', 'iss']).to.have.deep.property('claims', {
                id_token: {
                  auth_time: { essential: true },
                },
              });
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
                  error: 'request_uri_not_supported',
                });
            });

            it('remaps invalid_redirect_uri error to invalid_request', async function () {
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

              expect(await this.provider.PushedAuthorizationRequest.find(id)).to.be.ok.and.have.property('consumed').and.is.ok;
            });

            it('allows the request_uri to be used (when request object was not used but client has request_object_signing_alg for its optional use)', async function () {
              const { body: { request_uri } } = await this.agent.post('/request')
                .auth('client-alg-registered', 'secret')
                .type('form')
                .send({
                  scope: 'openid',
                  response_type: 'code',
                  client_id: 'client-alg-registered',
                  iss: 'client-alg-registered',
                  aud: this.provider.issuer,
                });

              let id = request_uri.split(':');
              id = id[id.length - 1];

              expect(await this.provider.PushedAuthorizationRequest.find(id)).to.be.ok;

              const auth = new this.AuthorizationRequest({
                client_id: 'client-alg-registered',
                iss: 'client-alg-registered',
                aud: this.provider.issuer,
                state: undefined,
                redirect_uri: undefined,
                request_uri,
              });

              await this.wrap({ route: '/auth', verb: 'get', auth })
                .expect(303)
                .expect(auth.validatePresence(['code']));

              expect(await this.provider.PushedAuthorizationRequest.find(id)).to.be.ok.and.have.property('consumed').and.is.ok;
            });
          });
        });
      });
    });
  });

  context('with Request Objects', () => {
    before(bootstrap(import.meta.url, { config: 'pushed_authorization_requests_jar' }));

    before(async function () {
      const client = await this.provider.Client.find('client');
      this.key = await importJWK(client.symmetricKeyStore.selectForSign({ alg: 'HS256' })[0]);
    });

    describe('discovery', () => {
      it('extends the well known config', async function () {
        await this.agent.get('/.well-known/openid-configuration')
          .expect((response) => {
            expect(response.body).not.to.have.property('request_object_endpoint');
            expect(response.body).to.have.property('pushed_authorization_request_endpoint');
            expect(response.body).to.have.property('request_object_signing_alg_values_supported').with.not.lengthOf(0);
            expect(response.body).to.have.property('request_parameter_supported', true);
            expect(response.body).to.have.property('request_uri_parameter_supported', false);
            expect(response.body).not.to.have.property('require_pushed_authorization_requests');
          });

        i(this.provider).features.pushedAuthorizationRequests
          .requirePushedAuthorizationRequests = true;

        return this.agent.get('/.well-known/openid-configuration')
          .expect((response) => {
            expect(response.body).to.have.property('require_pushed_authorization_requests', true);
          });
      });

      after(function () {
        i(this.provider).features.pushedAuthorizationRequests
          .requirePushedAuthorizationRequests = false;
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
                jti: randomBytes(16).toString('base64url'),
                response_type: 'code',
                client_id: clientId,
                iss: clientId,
                aud: this.provider.issuer,
              }, this.key, 'HS256', { expiresIn: 30 }).then((request) => {
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
                    jti: randomBytes(16).toString('base64url'),
                    response_type: 'code',
                    client_id: clientId,
                    extra: 'provided',
                    iss: clientId,
                    aud: this.provider.issuer,
                  }, this.key, 'HS256', {
                    expiresIn: 30,
                  }),
                })
                .expect(201)
                .expect(({ body }) => {
                  expect(body).to.have.keys('expires_in', 'request_uri');
                  expect(body).to.have.property('expires_in').closeTo(30, 1);
                  expect(body).to.have.property('request_uri').and.match(/^urn:ietf:params:oauth:request_uri:(.+)$/);
                });

              expect(spy).to.have.property('calledOnce', true);
              expect(spy.args[0][0].oidc.params).to.include({
                extra: 'provided',
                extra2: 'defaulted',
              });
            });

            it('defaults to MAX_TTL when no expires_in is present', async function () {
              const spy = sinon.spy();
              this.provider.once('pushed_authorization_request.success', spy);

              await this.agent.post('/request')
                .auth(clientId, 'secret')
                .type('form')
                .send({
                  request: await JWT.sign({
                    jti: randomBytes(16).toString('base64url'),
                    response_type: 'code',
                    client_id: clientId,
                    iss: clientId,
                    aud: this.provider.issuer,
                  }, this.key, 'HS256'),
                })
                .expect(201)
                .expect(({ body }) => {
                  expect(body).to.have.property('expires_in').closeTo(60, 1);
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
                    jti: randomBytes(16).toString('base64url'),
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
                    jti: randomBytes(16).toString('base64url'),
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
                  expect(body).to.have.property('expires_in').closeTo(60, 1);
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
                    jti: randomBytes(16).toString('base64url'),
                    response_type: 'code',
                    client_id: clientId,
                    iss: clientId,
                    aud: this.provider.issuer,
                  }, this.key, 'HS256', { expiresIn: 30 }),
                })
                .expect(201);

              expect(spy).to.have.property('calledOnce', true);
              const { request } = spy.args[0][0];
              const payload = decodeJwt(request);
              expect(payload).not.to.have.property('nonce');
              expect(payload).to.have.property('response_type', 'code');
            });

            it('requires the registered request object signing alg be used', async function () {
              return this.agent.post('/request')
                .auth('client-alg-registered', 'secret')
                .type('form')
                .send({
                  request: await JWT.sign({
                    jti: randomBytes(16).toString('base64url'),
                    response_type: 'code',
                    client_id: 'client-alg-registered',
                  }, this.key, 'HS384'),
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
                    jti: randomBytes(16).toString('base64url'),
                    response_type: 'code',
                    client_id: 'client-foo',
                  }, this.key, 'HS256', { expiresIn: 30 }),
                })
                .expect(400)
                .expect({
                  error: 'invalid_request_object',
                  error_description: "request client_id must equal the authenticated client's client_id",
                });
            });

            it('remaps invalid_redirect_uri error to invalid_request', async function () {
              return this.agent.post('/request')
                .auth(clientId, 'secret')
                .type('form')
                .send({
                  request: await JWT.sign({
                    jti: randomBytes(16).toString('base64url'),
                    response_type: 'code',
                    client_id: clientId,
                    iss: clientId,
                    aud: this.provider.issuer,
                    redirect_uri: 'https://rp.example.com/unlisted',
                  }, this.key, 'HS256', { expiresIn: 30 }),
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
                    jti: randomBytes(16).toString('base64url'),
                    response_type: 'code',
                    client_id: clientId,
                    iss: clientId,
                    aud: this.provider.issuer,
                  }, this.key, 'HS256', { expiresIn: 30 }),
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
                    jti: randomBytes(16).toString('base64url'),
                    scope: 'openid',
                    response_type: 'code',
                    client_id: clientId,
                    iss: clientId,
                    aud: this.provider.issuer,
                  }, this.key, 'HS256', { expiresIn: 30 }),
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

              expect(await this.provider.PushedAuthorizationRequest.find(id)).to.be.ok.and.have.property('consumed').and.is.ok;
            });

            it('handles expired or invalid pushed authorization request object', async function () {
              const auth = new this.AuthorizationRequest({
                client_id: clientId,
                request_uri: 'urn:ietf:params:oauth:request_uri:foobar',
              });

              return this.wrap({ route: '/auth', verb: 'get', auth })
                .expect(303)
                .expect(auth.validatePresence(['error', 'error_description', 'state']))
                .expect(auth.validateState)
                .expect(auth.validateClientLocation)
                .expect(auth.validateError('invalid_request_uri'))
                .expect(auth.validateErrorDescription('request_uri is invalid, expired, or was already used'));
            });
          });
        });
      });
    });
  });
});
