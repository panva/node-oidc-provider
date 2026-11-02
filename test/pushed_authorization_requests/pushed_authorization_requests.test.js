import { describe, before, it, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { parse as parseUrl } from 'node:url';

import sinon from 'sinon';
import { importJWK, decodeProtectedHeader, decodeJwt } from 'jose';

import * as JWT from '../../lib/helpers/jwt.js';
import bootstrap from '../test_helper.js';

describe('Pushed Request Object', () => {
  const fixture = {};

  describe('w/o Request Objects', () => {
    const fixture1 = Object.create(fixture);

    before(bootstrap(import.meta.url, fixture1), { timeout: 3000 });

    describe('discovery', () => {
      const fixture2 = Object.create(fixture1);

      it('extends the well known config', { timeout: 3000 }, async () => {
        await fixture2.agent.get('/.well-known/openid-configuration')
          .expect((response) => {
            assert.ok(!('request_object_endpoint' in Object(response.body)));
            assert.ok('pushed_authorization_request_endpoint' in Object(response.body));
            assert.ok(!('request_object_signing_alg_values_supported' in Object(response.body)));
            ((actual) => { assert.ok('request_uri_parameter_supported' in Object(actual)); assert.equal(actual.request_uri_parameter_supported, false); })(response.body);
            assert.ok(!('require_pushed_authorization_requests' in Object(response.body)));
          });

        i(fixture2.provider).features.pushedAuthorizationRequests
          .requirePushedAuthorizationRequests = true;

        return fixture2.agent.get('/.well-known/openid-configuration')
          .expect((response) => {
            ((actual) => { assert.ok('require_pushed_authorization_requests' in Object(actual)); assert.equal(actual.require_pushed_authorization_requests, true); })(response.body);
          });
      });

      after(() => {
        i(fixture2.provider).features.pushedAuthorizationRequests
          .requirePushedAuthorizationRequests = false;
      }, { timeout: 3000 });
    });

    describe('claims validation', () => {
      const fixture3 = Object.create(fixture1);

      for (const container of ['userinfo', 'id_token']) {
        const claims = {
          [container]: {
            verified_claims: [{
              verification: { trust_framework: { value: 'eidas' } },
              claims: { given_name: null, family_name: null },
            }],
          },
        };

        it(`rejects claims.${container} arrays by default`, { timeout: 3000 }, async () => {
          await fixture3.agent.post('/request')
            .auth('client', 'secret')
            .type('form')
            .send({
              client_id: 'client',
              scope: 'openid',
              response_type: 'code',
              claims: JSON.stringify(claims),
            })
            .expect(400)
            .expect({
              error: 'invalid_request',
              error_description: `claims.${container} members must be null or objects`,
            });
        });

        it(`can accept claims.${container} arrays with custom validation`, { timeout: 3000 }, async () => {
          const assertion = sinon.stub(i(fixture3.provider).features.claimsParameter, 'assertClaimsParameter').resolves();

          try {
            const { body: { request_uri } } = await fixture3.agent.post('/request')
              .auth('client', 'secret')
              .type('form')
              .send({
                client_id: 'client',
                scope: 'openid',
                response_type: 'code',
                claims: JSON.stringify(claims),
              })
              .expect(201);

            assert.equal(assertion.calledOnce, true);
            assert.deepEqual(assertion.firstCall.args[1], claims);
            const stored = await fixture3.provider.PushedAuthorizationRequest.find(request_uri.split(':').at(-1));
            assert.deepEqual(decodeJwt(stored.request).claims, claims);
          } finally {
            assertion.restore();
          }
        });
      }
    });

    describe('trust metadata for public clients', () => {
      const fixture4 = Object.create(fixture1);

      before(() => fixture4.login(), { timeout: 3000 });
      after(() => fixture4.logout(), { timeout: 3000 });

      it('does not mark parameters from an unauthenticated plain PAR as trusted', { timeout: 3000 }, async () => {
        const clientId = 'client-unregistered-test-public';
        const parameters = new fixture4.AuthorizationRequest({
          client_id: clientId,
          response_type: 'code',
          scope: 'openid',
        });
        const { body: { request_uri } } = await fixture4.agent.post('/request')
          .type('form')
          .send({
            client_id: clientId,
            response_type: parameters.response_type,
            scope: parameters.scope,
            redirect_uri: parameters.redirect_uri,
            code_challenge: parameters.code_challenge,
            code_challenge_method: parameters.code_challenge_method,
          })
          .expect(201);

        const id = request_uri.split(':').at(-1);
        ((actual) => { assert.ok('trusted' in Object(actual)); assert.equal(actual.trusted, false); })(await fixture4.provider.PushedAuthorizationRequest.find(id));

        const authorizationSuccess = sinon.spy();
        fixture4.provider.once('authorization.success', authorizationSuccess);
        const auth = new fixture4.AuthorizationRequest({
          client_id: clientId,
          request_uri,
          state: undefined,
          redirect_uri: undefined,
        });

        await fixture4.wrap({ route: '/auth', verb: 'get', auth })
          .expect(303)
          .expect(auth.validatePresence(['code']));

        assert.equal(authorizationSuccess.calledOnce, true);
        assert.equal(authorizationSuccess.firstCall.args[0].oidc.trusted, undefined);
      });
    });

    ['client', 'client-par-required'].forEach((clientId) => {
      const requirePushedAuthorizationRequests = clientId === 'client-par-required';

      describe('allowUnregisteredRedirectUris', () => {
        const fixture5 = Object.create(fixture1);

        before(() => {
          i(fixture5.provider).features.pushedAuthorizationRequests
            .allowUnregisteredRedirectUris = true;
        }, { timeout: 3000 });
        after(() => {
          i(fixture5.provider).features.pushedAuthorizationRequests
            .allowUnregisteredRedirectUris = false;
        }, { timeout: 3000 });
        before(() => fixture5.login(), { timeout: 3000 });
        after(() => fixture5.logout(), { timeout: 3000 });

        it('allows unregistered redirect_uris to be used', { timeout: 3000 }, async () => {
          const { body: { request_uri } } = await fixture5.agent.post('/request')
            .auth(clientId, 'secret')
            .type('form')
            .send({
              scope: 'openid',
              response_type: 'code',
              client_id: clientId,
              iss: clientId,
              aud: fixture5.provider.issuer,
              redirect_uri: 'https://rp.example.com/unlisted',
            })
            .expect(201);

          let id = request_uri.split(':');
          id = id[id.length - 1];

          const { request } = await fixture5.provider.PushedAuthorizationRequest.find(id);
          ((actual) => { assert.ok('redirect_uri' in Object(actual)); assert.equal(actual.redirect_uri, 'https://rp.example.com/unlisted'); })(decodeJwt(request));

          const auth = new fixture5.AuthorizationRequest({
            client_id: clientId,
            iss: clientId,
            aud: fixture5.provider.issuer,
            state: undefined,
            redirect_uri: undefined,
            request_uri,
          });

          let code;
          await fixture5.wrap({ route: '/auth', verb: 'get', auth })
            .expect(303)
            .expect(auth.validatePresence(['code']))
            .expect((response) => {
              ({ query: { code } } = parseUrl(response.headers.location, true));
              const jti = fixture5.getTokenJti(code);
              ((actual) => { assert.ok('redirectUri' in Object(actual)); assert.equal(actual.redirectUri, 'https://rp.example.com/unlisted'); })(fixture5.TestAdapter.for('AuthorizationCode').syncFind(jti));
            });

          return fixture5.agent.post('/token')
            .auth(clientId, 'secret')
            .type('form')
            .send({
              code,
              grant_type: 'authorization_code',
              redirect_uri: 'https://rp.example.com/unlisted',
            })
            .expect(200);
        });

        it('except for public clients', { timeout: 3000 }, async () => {
          const testClientId = 'client-unregistered-test-public';
          return fixture5.agent.post('/request')
            .type('form')
            .send({
              response_type: 'code',
              client_id: testClientId,
              iss: testClientId,
              aud: fixture5.provider.issuer,
              redirect_uri: 'https://rp.example.com/unlisted',
            })
            .expect(400)
            .expect({
              error: 'invalid_request',
              error_description: "redirect_uri did not match any of the client's registered redirect_uris",
            });
        });

        it('still validates the URI to be valid redirect_uri', { timeout: 3000 }, async () => {
          // must only contain valid uris
          await fixture5.agent.post('/request')
            .auth(clientId, 'secret')
            .type('form')
            .send({
              scope: 'openid',
              response_type: 'code',
              client_id: clientId,
              iss: clientId,
              aud: fixture5.provider.issuer,
              redirect_uri: 'not-a-valid-uri',
            })
            .expect(400)
            .expect({
              error: 'invalid_request',
              error_description: 'redirect_uri must only contain valid uris',
            });

          // must not contain fragments
          await fixture5.agent.post('/request')
            .auth(clientId, 'secret')
            .type('form')
            .send({
              scope: 'openid',
              response_type: 'code',
              client_id: clientId,
              iss: clientId,
              aud: fixture5.provider.issuer,
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
        const fixture6 = Object.create(fixture1);

        describe('using a JAR request parameter', () => {
          const fixture7 = Object.create(fixture6);

          it('is not enabled', { timeout: 3000 }, async () => fixture7.agent.post('/request')
              .auth(clientId, 'secret')
              .type('form')
              .send({
                client_id: clientId,
                request: 'this.should.be.a.jwt',
              })
              .expect(400)
              .expect({
                error: 'request_not_supported',
              }));
        });

        describe('using a plain pushed authorization request', () => {
          const fixture8 = Object.create(fixture6);

          describe('Pushed Authorization Request Endpoint', () => {
            const fixture9 = Object.create(fixture8);

            it('populates ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
              fixture9.assertOnce((ctx) => {
                assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Client', 'PushedAuthorizationRequest']));
              }, done);

              fixture9.agent.post('/request')
                .auth(clientId, 'secret')
                .type('form')
                .send({
                  response_type: 'code',
                  client_id: clientId,
                  iss: clientId,
                  aud: fixture9.provider.issuer,
                })
                .end(() => {});
            });

            it('stores a request object and returns a uri', { timeout: 3000 }, async () => {
              const spy = sinon.spy();
              fixture9.provider.once('pushed_authorization_request.success', spy);
              const spy2 = sinon.spy();
              fixture9.provider.once('pushed_authorization_request.saved', spy2);

              await fixture9.agent.post('/request')
                .auth(clientId, 'secret')
                .type('form')
                .send({
                  scope: 'openid',
                  response_type: 'code',
                  client_id: clientId,
                  iss: clientId,
                  extra: 'provided',
                  aud: fixture9.provider.issuer,
                  claims: JSON.stringify({
                    id_token: {
                      auth_time: { essential: true },
                    },
                  }),
                })
                .expect(201)
                .expect(({ body }) => {
                  assert.deepEqual(new Set(Object.keys(body)), new Set(['expires_in', 'request_uri']));
                  ((actual) => { assert.ok('expires_in' in Object(actual)); ((value) => { assert.equal(typeof value, 'number'); assert.ok(Math.abs((value) - (60)) <= (1)); })(actual.expires_in); })(body);
                  ((actual) => { assert.ok('request_uri' in Object(actual)); assert.match(actual.request_uri, /^urn:ietf:params:oauth:request_uri:(.+)$/); })(body);
                });

              ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
              ((actual) => { assert.ok("extra" in Object(actual)); assert.equal(actual.extra, 'provided'); assert.ok("extra2" in Object(actual)); assert.equal(actual.extra2, 'defaulted'); })(spy.args[0][0].oidc.params);
              ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy2);
              const stored = spy2.args[0][0];
              ((actual) => { assert.ok('trusted' in Object(actual)); assert.equal(actual.trusted, true); })(stored);
              const header = decodeProtectedHeader(stored.request);
              assert.deepEqual(header, { alg: 'none' });
              const payload = decodeJwt(stored.request);
              ((actual) => { assert.ok(['aud', 'exp', 'iat', 'nbf', 'iss'].every((key) => Object.keys(actual).includes(key))); assert.ok('claims' in Object(actual)); assert.deepEqual(actual.claims, {
                id_token: {
                  auth_time: { essential: true },
                },
              }); })(payload);
            });

            it('forbids request_uri to be used', { timeout: 3000 }, async () => fixture9.agent.post('/request')
                .auth(clientId, 'secret')
                .type('form')
                .send({
                  response_type: 'code',
                  request_uri: 'https://rp.example.com/jar#foo',
                })
                .expect(400)
                .expect({
                  error: 'request_uri_not_supported',
                }));

            it('remaps invalid_redirect_uri error to invalid_request', { timeout: 3000 }, async () => fixture9.agent.post('/request')
                .auth(clientId, 'secret')
                .type('form')
                .send({
                  response_type: 'code',
                  client_id: clientId,
                  iss: clientId,
                  aud: fixture9.provider.issuer,
                  redirect_uri: 'https://rp.example.com/unlisted',
                })
                .expect(400)
                .expect({
                  error: 'invalid_request',
                  error_description: "redirect_uri did not match any of the client's registered redirect_uris",
                }));

            it('leaves non OIDCProviderError alone', { timeout: 3000 }, async () => {
              const adapterThrow = new Error('adapter throw!');
              sinon.stub(fixture9.TestAdapter.for('PushedAuthorizationRequest'), 'upsert').callsFake(async () => { throw adapterThrow; });
              return fixture9.agent.post('/request')
                .auth(clientId, 'secret')
                .type('form')
                .send({
                  response_type: 'code',
                  client_id: clientId,
                  iss: clientId,
                  aud: fixture9.provider.issuer,
                })
                .expect(() => {
                  fixture9.TestAdapter.for('PushedAuthorizationRequest').upsert.restore();
                })
                .expect(500)
                .expect({
                  error: 'server_error',
                  error_description: 'oops! something went wrong',
                });
            });
          });

          describe('Using Pushed Authorization Requests', () => {
            const fixture10 = Object.create(fixture8);

            before(() => fixture10.login(), { timeout: 3000 });
            after(() => fixture10.logout(), { timeout: 3000 });

            it('allows the request_uri to be used', { timeout: 3000 }, async () => {
              const authorizationSuccess = sinon.spy();
              fixture10.provider.once('authorization.success', authorizationSuccess);

              const { body: { request_uri } } = await fixture10.agent.post('/request')
                .auth(clientId, 'secret')
                .type('form')
                .send({
                  scope: 'openid',
                  response_type: 'code',
                  client_id: clientId,
                  iss: clientId,
                  aud: fixture10.provider.issuer,
                });

              let id = request_uri.split(':');
              id = id[id.length - 1];

              assert.ok(await fixture10.provider.PushedAuthorizationRequest.find(id));

              const auth = new fixture10.AuthorizationRequest({
                client_id: clientId,
                iss: clientId,
                aud: fixture10.provider.issuer,
                state: undefined,
                redirect_uri: undefined,
                request_uri,
              });

              await fixture10.wrap({ route: '/auth', verb: 'get', auth })
                .expect(303)
                .expect(auth.validatePresence(['code']));

              assert.equal(authorizationSuccess.calledOnce, true);
              ((actual) => { assert.ok(Array.isArray(actual)); assert.ok(['client_id', 'response_type', 'scope'].every((value) => actual.includes(value))); assert.ok(!(actual.includes('request_uri'))); })(authorizationSuccess.firstCall.args[0].oidc.trusted);
              ((actual) => { assert.ok(actual); assert.ok('consumed' in Object(actual)); assert.ok(actual.consumed); })(await fixture10.provider.PushedAuthorizationRequest.find(id));
            });

            it('allows the request_uri to be used (when request object was not used but client has request_object_signing_alg for its optional use)', { timeout: 3000 }, async () => {
              const { body: { request_uri } } = await fixture10.agent.post('/request')
                .auth('client-alg-registered', 'secret')
                .type('form')
                .send({
                  scope: 'openid',
                  response_type: 'code',
                  client_id: 'client-alg-registered',
                  iss: 'client-alg-registered',
                  aud: fixture10.provider.issuer,
                });

              let id = request_uri.split(':');
              id = id[id.length - 1];

              assert.ok(await fixture10.provider.PushedAuthorizationRequest.find(id));

              const auth = new fixture10.AuthorizationRequest({
                client_id: 'client-alg-registered',
                iss: 'client-alg-registered',
                aud: fixture10.provider.issuer,
                state: undefined,
                redirect_uri: undefined,
                request_uri,
              });

              await fixture10.wrap({ route: '/auth', verb: 'get', auth })
                .expect(303)
                .expect(auth.validatePresence(['code']));

              ((actual) => { assert.ok(actual); assert.ok('consumed' in Object(actual)); assert.ok(actual.consumed); })(await fixture10.provider.PushedAuthorizationRequest.find(id));
            });
          });
        });
      });
    });
  });

  describe('with Request Objects', () => {
    const fixture11 = Object.create(fixture);

    before(bootstrap(import.meta.url, fixture11, { config: 'pushed_authorization_requests_jar' }), { timeout: 3000 });

    before(async () => {
      const client = await fixture11.provider.Client.find('client');
      fixture11.key = await importJWK(client.symmetricKeyStore.selectForSign({ alg: 'HS256' })[0]);
    }, { timeout: 3000 });

    describe('discovery', () => {
      const fixture12 = Object.create(fixture11);

      it('extends the well known config', { timeout: 3000 }, async () => {
        await fixture12.agent.get('/.well-known/openid-configuration')
          .expect((response) => {
            assert.ok(!('request_object_endpoint' in Object(response.body)));
            assert.ok('pushed_authorization_request_endpoint' in Object(response.body));
            ((actual) => { assert.ok('request_object_signing_alg_values_supported' in Object(actual)); assert.notEqual(actual.request_object_signing_alg_values_supported.length, 0); })(response.body);
            ((actual) => { assert.ok('request_parameter_supported' in Object(actual)); assert.equal(actual.request_parameter_supported, true); })(response.body);
            ((actual) => { assert.ok('request_uri_parameter_supported' in Object(actual)); assert.equal(actual.request_uri_parameter_supported, false); })(response.body);
            assert.ok(!('require_pushed_authorization_requests' in Object(response.body)));
          });

        i(fixture12.provider).features.pushedAuthorizationRequests
          .requirePushedAuthorizationRequests = true;

        return fixture12.agent.get('/.well-known/openid-configuration')
          .expect((response) => {
            ((actual) => { assert.ok('require_pushed_authorization_requests' in Object(actual)); assert.equal(actual.require_pushed_authorization_requests, true); })(response.body);
          });
      });

      after(() => {
        i(fixture12.provider).features.pushedAuthorizationRequests
          .requirePushedAuthorizationRequests = false;
      }, { timeout: 3000 });
    });

    ['client', 'client-par-required'].forEach((clientId) => {
      const requirePushedAuthorizationRequests = clientId === 'client-par-required';

      describe(`when require_pushed_authorization_requests=${requirePushedAuthorizationRequests}`, () => {
        const fixture13 = Object.create(fixture11);

        describe('using a JAR request parameter', () => {
          const fixture14 = Object.create(fixture13);

          describe('Pushed Authorization Request Endpoint', () => {
            const fixture15 = Object.create(fixture14);

            it('populates ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
              fixture15.assertOnce((ctx) => {
                assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Client', 'PushedAuthorizationRequest']));
              }, done);

              JWT.sign({
                jti: randomBytes(16).toString('base64url'),
                response_type: 'code',
                client_id: clientId,
                iss: clientId,
                aud: fixture15.provider.issuer,
              }, fixture15.key, 'HS256', { expiresIn: 30 }).then((request) => {
                fixture15.agent.post('/request')
                  .auth(clientId, 'secret')
                  .type('form')
                  .send({ request })
                  .end(() => {});
              });
            });

            it('stores a request object and returns a uri', { timeout: 3000 }, async () => {
              const spy = sinon.spy();
              fixture15.provider.once('pushed_authorization_request.success', spy);

              await fixture15.agent.post('/request')
                .auth(clientId, 'secret')
                .type('form')
                .send({
                  request: await JWT.sign({
                    jti: randomBytes(16).toString('base64url'),
                    response_type: 'code',
                    client_id: clientId,
                    extra: 'provided',
                    iss: clientId,
                    aud: fixture15.provider.issuer,
                  }, fixture15.key, 'HS256', {
                    expiresIn: 30,
                  }),
                })
                .expect(201)
                .expect(({ body }) => {
                  assert.deepEqual(new Set(Object.keys(body)), new Set(['expires_in', 'request_uri']));
                  ((actual) => { assert.ok('expires_in' in Object(actual)); ((value) => { assert.equal(typeof value, 'number'); assert.ok(Math.abs((value) - (30)) <= (1)); })(actual.expires_in); })(body);
                  ((actual) => { assert.ok('request_uri' in Object(actual)); assert.match(actual.request_uri, /^urn:ietf:params:oauth:request_uri:(.+)$/); })(body);
                });

              ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
              ((actual) => { assert.ok("extra" in Object(actual)); assert.equal(actual.extra, 'provided'); assert.ok("extra2" in Object(actual)); assert.equal(actual.extra2, 'defaulted'); })(spy.args[0][0].oidc.params);
            });

            it('defaults to MAX_TTL when no expires_in is present', { timeout: 3000 }, async () => {
              const spy = sinon.spy();
              fixture15.provider.once('pushed_authorization_request.success', spy);

              await fixture15.agent.post('/request')
                .auth(clientId, 'secret')
                .type('form')
                .send({
                  request: await JWT.sign({
                    jti: randomBytes(16).toString('base64url'),
                    response_type: 'code',
                    client_id: clientId,
                    iss: clientId,
                    aud: fixture15.provider.issuer,
                  }, fixture15.key, 'HS256'),
                })
                .expect(201)
                .expect(({ body }) => {
                  ((actual) => { assert.ok('expires_in' in Object(actual)); ((value) => { assert.equal(typeof value, 'number'); assert.ok(Math.abs((value) - (60)) <= (1)); })(actual.expires_in); })(body);
                });

              ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
            });

            it('uses the expiration from JWT when below MAX_TTL', { timeout: 3000 }, async () => {
              const spy = sinon.spy();
              fixture15.provider.once('pushed_authorization_request.success', spy);

              await fixture15.agent.post('/request')
                .auth(clientId, 'secret')
                .type('form')
                .send({
                  request: await JWT.sign({
                    jti: randomBytes(16).toString('base64url'),
                    response_type: 'code',
                    client_id: clientId,
                    iss: clientId,
                    aud: fixture15.provider.issuer,
                  }, fixture15.key, 'HS256', {
                    expiresIn: 20,
                  }),
                })
                .expect(201)
                .expect(({ body }) => {
                  assert.deepEqual(new Set(Object.keys(body)), new Set(['expires_in', 'request_uri']));
                  ((actual) => { assert.ok('expires_in' in Object(actual)); ((value) => { assert.equal(typeof value, 'number'); assert.ok(Math.abs((value) - (20)) <= (1)); })(actual.expires_in); })(body);
                  ((actual) => { assert.ok('request_uri' in Object(actual)); assert.match(actual.request_uri, /^urn:ietf:params:oauth:request_uri:(.+)$/); })(body);
                });

              ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
            });

            it('uses MAX_TTL when the expiration from JWT is above it', { timeout: 3000 }, async () => {
              const spy = sinon.spy();
              fixture15.provider.once('pushed_authorization_request.success', spy);

              await fixture15.agent.post('/request')
                .auth(clientId, 'secret')
                .type('form')
                .send({
                  request: await JWT.sign({
                    jti: randomBytes(16).toString('base64url'),
                    response_type: 'code',
                    client_id: clientId,
                    iss: clientId,
                    aud: fixture15.provider.issuer,
                  }, fixture15.key, 'HS256', {
                    expiresIn: 120,
                  }),
                })
                .expect(201)
                .expect(({ body }) => {
                  assert.deepEqual(new Set(Object.keys(body)), new Set(['expires_in', 'request_uri']));
                  ((actual) => { assert.ok('expires_in' in Object(actual)); ((value) => { assert.equal(typeof value, 'number'); assert.ok(Math.abs((value) - (60)) <= (1)); })(actual.expires_in); })(body);
                  ((actual) => { assert.ok('request_uri' in Object(actual)); assert.match(actual.request_uri, /^urn:ietf:params:oauth:request_uri:(.+)$/); })(body);
                });

              ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
            });

            it('ignores regular parameters when passing a JAR request', { timeout: 3000 }, async () => {
              const spy = sinon.spy();
              fixture15.provider.once('pushed_authorization_request.saved', spy);

              await fixture15.agent.post('/request')
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
                    aud: fixture15.provider.issuer,
                  }, fixture15.key, 'HS256', { expiresIn: 30 }),
                })
                .expect(201);

              ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
              const { request } = spy.args[0][0];
              const payload = decodeJwt(request);
              assert.ok(!('nonce' in Object(payload)));
              ((actual) => { assert.ok('response_type' in Object(actual)); assert.equal(actual.response_type, 'code'); })(payload);
            });

            it('requires the registered request object signing alg be used', { timeout: 3000 }, async () => fixture15.agent.post('/request')
                .auth('client-alg-registered', 'secret')
                .type('form')
                .send({
                  request: await JWT.sign({
                    jti: randomBytes(16).toString('base64url'),
                    response_type: 'code',
                    client_id: 'client-alg-registered',
                  }, fixture15.key, 'HS384'),
                })
                .expect(400)
                .expect({
                  error: 'invalid_request_object',
                  error_description: 'the preregistered alg must be used in request or request_uri',
                }));

            it('requires the request object client_id to equal the authenticated client one', { timeout: 3000 }, async () => fixture15.agent.post('/request')
                .auth(clientId, 'secret')
                .type('form')
                .send({
                  request: await JWT.sign({
                    jti: randomBytes(16).toString('base64url'),
                    response_type: 'code',
                    client_id: 'client-foo',
                  }, fixture15.key, 'HS256', { expiresIn: 30 }),
                })
                .expect(400)
                .expect({
                  error: 'invalid_request_object',
                  error_description: "request client_id must equal the authenticated client's client_id",
                }));

            it('remaps invalid_redirect_uri error to invalid_request', { timeout: 3000 }, async () => fixture15.agent.post('/request')
                .auth(clientId, 'secret')
                .type('form')
                .send({
                  request: await JWT.sign({
                    jti: randomBytes(16).toString('base64url'),
                    response_type: 'code',
                    client_id: clientId,
                    iss: clientId,
                    aud: fixture15.provider.issuer,
                    redirect_uri: 'https://rp.example.com/unlisted',
                  }, fixture15.key, 'HS256', { expiresIn: 30 }),
                })
                .expect(400)
                .expect({
                  error: 'invalid_request',
                  error_description: "redirect_uri did not match any of the client's registered redirect_uris",
                }));

            it('leaves non OIDCProviderError alone', { timeout: 3000 }, async () => {
              const adapterThrow = new Error('adapter throw!');
              sinon.stub(fixture15.TestAdapter.for('PushedAuthorizationRequest'), 'upsert').callsFake(async () => { throw adapterThrow; });
              return fixture15.agent.post('/request')
                .auth(clientId, 'secret')
                .type('form')
                .send({
                  request: await JWT.sign({
                    jti: randomBytes(16).toString('base64url'),
                    response_type: 'code',
                    client_id: clientId,
                    iss: clientId,
                    aud: fixture15.provider.issuer,
                  }, fixture15.key, 'HS256', { expiresIn: 30 }),
                })
                .expect(() => {
                  fixture15.TestAdapter.for('PushedAuthorizationRequest').upsert.restore();
                })
                .expect(500)
                .expect({
                  error: 'server_error',
                  error_description: 'oops! something went wrong',
                });
            });
          });

          describe('Using Pushed Authorization Requests', () => {
            const fixture16 = Object.create(fixture14);

            before(() => fixture16.login(), { timeout: 3000 });
            after(() => fixture16.logout(), { timeout: 3000 });

            it('allows the request_uri to be used', { timeout: 3000 }, async () => {
              const authorizationSuccess = sinon.spy();
              fixture16.provider.once('authorization.success', authorizationSuccess);

              const { body: { request_uri } } = await fixture16.agent.post('/request')
                .auth(clientId, 'secret')
                .type('form')
                .send({
                  request: await JWT.sign({
                    jti: randomBytes(16).toString('base64url'),
                    scope: 'openid',
                    response_type: 'code',
                    client_id: clientId,
                    iss: clientId,
                    aud: fixture16.provider.issuer,
                  }, fixture16.key, 'HS256', { expiresIn: 30 }),
                });

              let id = request_uri.split(':');
              id = id[id.length - 1];

              assert.ok(await fixture16.provider.PushedAuthorizationRequest.find(id));

              const auth = new fixture16.AuthorizationRequest({
                client_id: clientId,
                iss: clientId,
                aud: fixture16.provider.issuer,
                state: undefined,
                redirect_uri: undefined,
                request_uri,
              });

              await fixture16.wrap({ route: '/auth', verb: 'get', auth })
                .expect(303)
                .expect(auth.validatePresence(['code']));

              assert.equal(authorizationSuccess.calledOnce, true);
              ((actual) => { assert.ok(Array.isArray(actual)); assert.ok(['client_id', 'response_type', 'scope'].every((value) => actual.includes(value))); assert.ok(!(actual.includes('request_uri'))); })(authorizationSuccess.firstCall.args[0].oidc.trusted);
              ((actual) => { assert.ok(actual); assert.ok('consumed' in Object(actual)); assert.ok(actual.consumed); })(await fixture16.provider.PushedAuthorizationRequest.find(id));
            });

            it('handles expired or invalid pushed authorization request object', { timeout: 3000 }, async () => {
              const auth = new fixture16.AuthorizationRequest({
                client_id: clientId,
                request_uri: 'urn:ietf:params:oauth:request_uri:foobar',
              });

              return fixture16.wrap({ route: '/auth', verb: 'get', auth })
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
