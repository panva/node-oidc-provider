import { describe, before, it, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import { parse } from 'node:url';

import { importJWK } from 'jose';
import sinon from 'sinon';

import * as JWT from '../../lib/helpers/jwt.js';
import bootstrap from '../test_helper.js';

describe('request parameter features', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  describe('configuration features.request', () => {
    const fixture1 = Object.create(fixture);

    it('extends discovery', { timeout: 3000 }, async () => {
      await fixture1.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect((response) => {
          ((actual) => { assert.ok('request_parameter_supported' in Object(actual)); assert.equal(actual.request_parameter_supported, true); })(response.body);
          assert.ok(!('require_signed_request_object' in Object(response.body)));
        });

      i(fixture1.provider).features.requestObjects.requireSignedRequestObject = true;

      await fixture1.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect((response) => {
          ((actual) => { assert.ok('request_parameter_supported' in Object(actual)); assert.equal(actual.request_parameter_supported, true); })(response.body);
          ((actual) => { assert.ok('require_signed_request_object' in Object(actual)); assert.equal(actual.require_signed_request_object, true); })(response.body);
        });
    });

    after(() => {
      i(fixture1.provider).features.requestObjects.requireSignedRequestObject = false;
    }, { timeout: 3000 });
  });

  function redirectSuccess(response) {
    const expected = parse('https://client.example.com/cb', true);
    const actual = parse(response.headers.location, true);
    ['protocol', 'host', 'pathname'].forEach((attr) => {
      assert.equal(actual[attr], expected[attr]);
    });
    assert.ok('code' in Object(actual.query));
  }
  function httpSuccess({ body }) {
    assert.ok(['device_code'].every((key) => Object.keys(body).includes(key)));
  }

  [
    ['/auth', 'get', 'authorization.error', 303, 303, redirectSuccess, 'authorization.success'],
    ['/auth', 'post', 'authorization.error', 303, 303, redirectSuccess, 'authorization.success'],
    ['/device/auth', 'post', 'device_authorization.error', 200, 400, httpSuccess, 'device_authorization.success'],
  ].forEach(([
    route, verb, errorEvt, successCode, errorCode, successFnCheck, successEvt,
  ]) => {
    describe(`${route} ${verb} passing request parameters as JWTs`, () => {
      const fixture2 = Object.create(fixture);

      before(() => fixture2.login({
          claims: { id_token: { email: null } },
        }), { timeout: 3000 });
      after(() => {
        i(fixture2.provider).configuration.clockTolerance = 0;
        return fixture2.logout();
      }, { timeout: 3000 });
      if (route === '/auth') {
        beforeEach(() => {
          fixture2.code_challenge_method = 'S256';
          fixture2.code_verifier = crypto.randomBytes(32).toString('base64url');
          fixture2.code_challenge = crypto.hash('sha256', fixture2.code_verifier, 'base64url');
        }, { timeout: 3000 });
      }

      it('does not use anything from the OAuth 2.0 parameters', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture2.provider.once('authorization.success', spy);

        if (successCode === 200) {
          fixture2.provider.once('device_authorization.success', ({ oidc }) => {
            fixture2.provider.emit('authorization.success', { oidc: { params: oidc.entities.DeviceCode.params } });
          });
        }

        await JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: fixture2.code_challenge_method,
          code_challenge: fixture2.code_challenge,
          scope: 'openid',
        }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: fixture2.provider.issuer, expiresIn: 30 }).then((request) => fixture2.wrap({
          agent: fixture2.agent,
          route,
          verb,
          auth: {
            request,
            ui_locales: 'foo',
            client_id: 'client',
          },
        })
          .expect(successCode)
          .expect(successFnCheck)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
            assert.equal(spy.args[0][0].oidc.params.ui_locales, undefined);
          }));
      });

      if (route === '/auth') {
        it('preserves JSON object semantics for Claims requests', { timeout: 3000 }, async () => {
          const claims = {
            constructor: null,
            id_token: {
              constructor: null,
              email: { constructor: null },
            },
          };
          const request = await JWT.sign({
            jti: crypto.randomBytes(16).toString('base64url'),
            client_id: 'client',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
            code_challenge_method: fixture2.code_challenge_method,
            code_challenge: fixture2.code_challenge,
            scope: 'openid',
            max_age: 3600,
            claims,
          }, Buffer.from('secret'), 'HS256', {
            issuer: 'client',
            audience: fixture2.provider.issuer,
            expiresIn: 30,
          });
          const spy = sinon.spy();
          fixture2.provider.once('authorization.success', spy);

          return fixture2.wrap({
            agent: fixture2.agent,
            route,
            verb,
            auth: {
              request,
              client_id: 'client',
            },
          })
            .expect(303)
            .expect(redirectSuccess)
            .expect(() => {
              assert.equal(spy.calledOnce, true);
              const { oidc } = spy.args[0][0];
              assert.deepEqual(JSON.parse(oidc.params.claims), claims);
              assert.ok(oidc.requestParamClaims.has('email'));
              assert.ok(['constructor', 'email', 'auth_time'].every((key) => Object.keys(oidc.claims.id_token).includes(key)));
            });
        });
      }

      it('treats empty Request Object parameter values as omitted', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        const succeeds = successCode === 200;
        fixture2.provider.once(succeeds ? 'authorization.success' : errorEvt, spy);

        if (succeeds) {
          fixture2.provider.once('device_authorization.success', ({ oidc }) => {
            fixture2.provider.emit('authorization.success', { oidc: { params: oidc.entities.DeviceCode.params } });
          });
        }

        const request = await JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: fixture2.code_challenge_method,
          code_challenge: fixture2.code_challenge,
          scope: '',
        }, Buffer.from('secret'), 'HS256', {
          issuer: 'client',
          audience: fixture2.provider.issuer,
          expiresIn: 30,
        });

        return fixture2.wrap({
          agent: fixture2.agent,
          route,
          verb,
          auth: {
            request,
            client_id: 'client',
          },
        })
          .expect(successCode)
          .expect(succeeds ? successFnCheck : (response) => {
            const { query } = parse(response.headers.location, true);
            ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'access_denied'); })(query);
          })
          .expect(() => {
            assert.equal(spy.calledOnce, true);
            assert.equal(spy.args[0][0].oidc.params.scope, undefined);
          });
      });

      it('rejects an aud array containing a non-string member', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture2.provider.once(errorEvt, spy);

        await JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: fixture2.code_challenge_method,
          code_challenge: fixture2.code_challenge,
          scope: 'openid',
        }, Buffer.from('secret'), 'HS256', {
          issuer: 'client',
          audience: [fixture2.provider.issuer, null],
          expiresIn: 30,
        }).then((request) => fixture2.wrap({
          agent: fixture2.agent,
          route,
          verb,
          auth: {
            request,
            client_id: 'client',
          },
        })
          .expect(errorCode));

        assert.equal(spy.calledOnce, true);
        ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'invalid_request_object'); })(spy.args[0][1]);
        ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'Request Object claims are invalid'); })(spy.args[0][1]);
      });

      it('can contain max_age parameter as a number and it (and other params too) will be forced as string', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture2.provider.once(successEvt, spy);

        await JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client',
          response_type: 'code',
          scope: 'openid',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: fixture2.code_challenge_method,
          code_challenge: fixture2.code_challenge,
          max_age: 300,
        }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: fixture2.provider.issuer, expiresIn: 30 }).then((request) => fixture2.wrap({
          agent: fixture2.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(successCode)
          .expect(successFnCheck));

        assert.equal(spy.calledWithMatch({ oidc: { params: { max_age: sinon.match.string } } }), true);
      });

      it('can contain params as array and have them handled as dupes', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture2.provider.once(errorEvt, spy);

        return JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client',
          response_type: 'code',
          scope: ['openid', 'profile'],
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: fixture2.code_challenge_method,
          code_challenge: fixture2.code_challenge,
        }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: fixture2.provider.issuer, expiresIn: 30 }).then((request) => fixture2.wrap({
          agent: fixture2.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
            ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'invalid_request'); })(spy.args[0][1]);
            ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, "'scope' parameter must not be provided twice"); })(spy.args[0][1]);
          }));
      });

      it('can contain claims parameter as JSON', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture2.provider.once(successEvt, spy);
        const claims = JSON.stringify({ id_token: { email: null } });

        await JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: fixture2.code_challenge_method,
          code_challenge: fixture2.code_challenge,
          scope: 'openid',
          claims,
        }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: fixture2.provider.issuer, expiresIn: 30 }).then((request) => fixture2.wrap({
          agent: fixture2.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(successCode)
          .expect(successFnCheck));

        assert.equal(spy.calledWithMatch({ oidc: { params: { claims } } }), true);
      });

      it('can contain claims parameter as object', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture2.provider.once(successEvt, spy);
        const claims = { id_token: { email: null } };

        await JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: fixture2.code_challenge_method,
          code_challenge: fixture2.code_challenge,
          claims: { id_token: { email: null } },
          scope: 'openid',
        }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: fixture2.provider.issuer, expiresIn: 30 }).then((request) => fixture2.wrap({
          agent: fixture2.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(successCode)
          .expect(successFnCheck));

        assert.equal(spy.calledWithMatch({ oidc: { params: { claims: JSON.stringify(claims) } } }), true);
      });

      it('can accept Request Objects issued within acceptable system clock skew', { timeout: 3000 }, async () => {
        const client = await fixture2.provider.Client.find('client-with-HS-sig');
        let [key] = client.symmetricKeyStore.selectForSign({ alg: 'HS256' });
        key = await importJWK(key);
        i(fixture2.provider).configuration.clockTolerance = 10;
        return JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          iat: Math.ceil(Date.now() / 1000) + 5,
          client_id: 'client-with-HS-sig',
          scope: 'openid',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: fixture2.code_challenge_method,
          code_challenge: fixture2.code_challenge,
        }, key, 'HS256', { issuer: 'client-with-HS-sig', audience: fixture2.provider.issuer, expiresIn: 30 }).then((request) => fixture2.wrap({
          agent: fixture2.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client-with-HS-sig',
            response_type: 'code',
          },
        })
          .expect(successCode)
          .expect(successFnCheck));
      });

      it('works with signed by an actual DSA', { timeout: 3000 }, async () => {
        const client = await fixture2.provider.Client.find('client-with-HS-sig');
        let [key] = client.symmetricKeyStore.selectForSign({ alg: 'HS256' });
        key = await importJWK(key);
        return JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client-with-HS-sig',
          scope: 'openid',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: fixture2.code_challenge_method,
          code_challenge: fixture2.code_challenge,
        }, key, 'HS256', { issuer: 'client-with-HS-sig', audience: fixture2.provider.issuer, expiresIn: 30 }).then((request) => fixture2.wrap({
          agent: fixture2.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client-with-HS-sig',
            response_type: 'code',
          },
        })
          .expect(successCode)
          .expect(successFnCheck));
      });

      it('rejects HMAC based requests when signed with an expired secret', { timeout: 3000 }, async () => {
        const client = await fixture2.provider.Client.find('client-with-HS-sig-expired');
        let [key] = client.symmetricKeyStore.selectForSign({ alg: 'HS256' });
        key = await importJWK(key);

        const spy = sinon.spy();
        fixture2.provider.once(errorEvt, spy);

        return JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client-with-HS-sig-expired',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: fixture2.code_challenge_method,
          code_challenge: fixture2.code_challenge,
        }, key, 'HS256', { issuer: 'client-with-HS-sig-expired', audience: fixture2.provider.issuer, expiresIn: 30 }).then((request) => fixture2.wrap({
          agent: fixture2.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client-with-HS-sig-expired',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
            ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'invalid_request_object'); })(spy.args[0][1]);
            ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'could not validate the Request Object - the client secret used for its signature is expired'); })(spy.args[0][1]);
          }));
      });

      it('doesnt allow request inception', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture2.provider.once(errorEvt, spy);

        return JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client',
          response_type: 'code',
          request: 'request inception',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: fixture2.code_challenge_method,
          code_challenge: fixture2.code_challenge,
        }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: fixture2.provider.issuer, expiresIn: 30 }).then((request) => fixture2.wrap({
          agent: fixture2.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
            ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'invalid_request_object'); })(spy.args[0][1]);
            ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'Request Object must not contain request or request_uri properties'); })(spy.args[0][1]);
          }));
      });

      it('doesnt allow requestUri inception', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture2.provider.once(errorEvt, spy);

        return JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client',
          response_type: 'code',
          request_uri: 'request uri inception',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: fixture2.code_challenge_method,
          code_challenge: fixture2.code_challenge,
        }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: fixture2.provider.issuer, expiresIn: 30 }).then((request) => fixture2.wrap({
          agent: fixture2.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
            ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'invalid_request_object'); })(spy.args[0][1]);
            ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'Request Object must not contain request or request_uri properties'); })(spy.args[0][1]);
          }));
      });

      if (route !== '/device/auth') {
        it('may contain a response_mode and it will be honoured', { timeout: 3000 }, () => JWT.sign({
            jti: crypto.randomBytes(16).toString('base64url'),
            client_id: 'client',
            response_type: 'code',
            response_mode: 'fragment',
            scope: 'openid',
            redirect_uri: 'https://client.example.com/cb',
            code_challenge_method: fixture2.code_challenge_method,
            code_challenge: fixture2.code_challenge,
          }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: fixture2.provider.issuer, expiresIn: 30 }).then((request) => fixture2.wrap({
            agent: fixture2.agent,
            route,
            verb,
            auth: {
              request,
              scope: 'openid',
              client_id: 'client',
              response_type: 'code',
            },
          })
            .expect(fixture2.AuthorizationRequest.prototype.validateFragment)
            .expect(successCode)
            .expect(successFnCheck)));

        it('checks the response mode from the request', { timeout: 3000 }, () => {
          const spy = sinon.spy();
          fixture2.provider.once(errorEvt, spy);

          return JWT.sign({
            jti: crypto.randomBytes(16).toString('base64url'),
            client_id: 'client',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
            code_challenge_method: fixture2.code_challenge_method,
            code_challenge: fixture2.code_challenge,
            response_mode: 'foo',
          }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: fixture2.provider.issuer, expiresIn: 30 }).then((request) => fixture2.wrap({
            agent: fixture2.agent,
            route,
            verb,
            auth: {
              request,
              scope: 'openid',
              client_id: 'client',
              response_type: 'code',
              response_mode: 'query',
            },
          })
            .expect(errorCode)
            .expect(() => {
              assert.equal(spy.calledOnce, true);
              ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'unsupported_response_mode'); })(spy.args[0][1]);
              ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'unsupported response_mode requested'); })(spy.args[0][1]);
            }));
        });

        it('doesnt allow response_type to differ', { timeout: 3000 }, () => {
          const spy = sinon.spy();
          fixture2.provider.once(errorEvt, spy);

          return JWT.sign({
            jti: crypto.randomBytes(16).toString('base64url'),
            client_id: 'client',
            response_type: 'id_token',
            redirect_uri: 'https://client.example.com/cb',
            code_challenge_method: fixture2.code_challenge_method,
            code_challenge: fixture2.code_challenge,
          }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: fixture2.provider.issuer, expiresIn: 30 }).then((request) => fixture2.wrap({
            agent: fixture2.agent,
            route,
            verb,
            auth: {
              request,
              scope: 'openid',
              client_id: 'client',
              response_type: 'code',
            },
          })
            .expect(errorCode)
            .expect(() => {
              assert.equal(spy.calledOnce, true);
              ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'invalid_request_object'); })(spy.args[0][1]);
              ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'request response_type must equal the one in request parameters'); })(spy.args[0][1]);
            }));
        });

        it('uses the state from the request even if its validations will fail', { timeout: 3000 }, () => {
          const spy = sinon.spy();
          fixture2.provider.once(errorEvt, spy);

          return JWT.sign({
            jti: crypto.randomBytes(16).toString('base64url'),
            client_id: 'client2',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
            code_challenge_method: fixture2.code_challenge_method,
            code_challenge: fixture2.code_challenge,
            state: 'foobar',
          }, Buffer.from('secret'), 'HS256', { issuer: 'client2', audience: fixture2.provider.issuer, expiresIn: 30 }).then((request) => fixture2.wrap({
            agent: fixture2.agent,
            route,
            verb,
            auth: {
              request,
              scope: 'openid',
              client_id: 'client',
              response_type: 'code',
            },
          })
            .expect(fixture2.AuthorizationRequest.prototype.validateResponseParameter.call({}, 'state', 'foobar'))
            .expect(errorCode)
            .expect(() => {
              assert.equal(spy.calledOnce, true);
              ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'invalid_request_object'); })(spy.args[0][1]);
              ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'request client_id must equal the one in request parameters'); })(spy.args[0][1]);
            }));
        });
      }

      it('doesnt allow client_id to differ', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture2.provider.once(errorEvt, spy);

        return JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client2',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: fixture2.code_challenge_method,
          code_challenge: fixture2.code_challenge,
        }, Buffer.from('secret'), 'HS256', { issuer: 'client2', audience: fixture2.provider.issuer, expiresIn: 30 }).then((request) => fixture2.wrap({
          agent: fixture2.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
            ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'invalid_request_object'); })(spy.args[0][1]);
            ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'request client_id must equal the one in request parameters'); })(spy.args[0][1]);
          }));
      });

      it('handles invalid signed looklike jwts', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture2.provider.once(errorEvt, spy);

        return fixture2.wrap({
          agent: fixture2.agent,
          route,
          verb,
          auth: {
            request: 'definitely.notsigned.jwt',
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
            ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'invalid_request_object'); })(spy.args[0][1]);
            ((actual) => { assert.ok('error_description' in Object(actual)); assert.match(actual.error_description, /could not parse Request Object/); })(spy.args[0][1]);
          });
      });

      it('rejects a Request Object whose payload is not a JSON object', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture2.provider.once(errorEvt, spy);
        const request = [
          Buffer.from(JSON.stringify({ alg: 'HS256' })).toString('base64url'),
          Buffer.from('null').toString('base64url'),
          'invalid-signature',
        ].join('.');

        await fixture2.wrap({
          agent: fixture2.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
          },
        })
          .expect(errorCode);

        assert.equal(spy.calledOnce, true);
        ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'invalid_request_object'); })(spy.args[0][1]);
        ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'could not parse Request Object'); })(spy.args[0][1]);
      });

      it('rejects a signed Request Object whose protected header is not a JSON object', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture2.provider.once(errorEvt, spy);
        const signingInput = [
          Buffer.from('null').toString('base64url'),
          Buffer.from('{}').toString('base64url'),
        ].join('.');
        const signature = crypto.createHmac('sha256', 'secret')
          .update(signingInput)
          .digest('base64url');
        const request = `${signingInput}.${signature}`;

        await fixture2.wrap({
          agent: fixture2.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
          },
        })
          .expect(errorCode);

        assert.equal(spy.calledOnce, true);
        ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'invalid_request_object'); })(spy.args[0][1]);
        ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'could not parse Request Object'); })(spy.args[0][1]);
      });

      it('doesnt allow clients with predefined alg to bypass this alg', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture2.provider.once(errorEvt, spy);

        return JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client-with-HS-sig',
          scope: 'openid',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: fixture2.code_challenge_method,
          code_challenge: fixture2.code_challenge,
        }, Buffer.from('secret'), 'HS512', { issuer: 'client-with-HS-sig', audience: fixture2.provider.issuer, expiresIn: 30 }).then((request) => fixture2.wrap({
          agent: fixture2.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client-with-HS-sig',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
            ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'invalid_request_object'); })(spy.args[0][1]);
            ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'the preregistered alg must be used in request or request_uri'); })(spy.args[0][1]);
          }));
      });

      it('unsupported algs must not be used', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture2.provider.once(errorEvt, spy);

        return JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: fixture2.code_challenge_method,
          code_challenge: fixture2.code_challenge,
        }, crypto.createSecretKey(crypto.randomBytes(48)), 'HS384', { issuer: 'client', audience: fixture2.provider.issuer, expiresIn: 30 }).then((request) => fixture2.wrap({
          agent: fixture2.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
            ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'invalid_request_object'); })(spy.args[0][1]);
            ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'unsupported signed request alg'); })(spy.args[0][1]);
          }));
      });

      it('bad signatures will be rejected', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture2.provider.once(errorEvt, spy);
        return JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: fixture2.code_challenge_method,
          code_challenge: fixture2.code_challenge,
        }, Buffer.from('not THE secret'), 'HS256', { issuer: 'client', audience: fixture2.provider.issuer, expiresIn: 30 }).then((request) => fixture2.wrap({
          agent: fixture2.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
            ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'invalid_request_object'); })(spy.args[0][1]);
            ((actual) => { assert.ok('error_description' in Object(actual)); assert.match(actual.error_description, /could not validate Request Object/); })(spy.args[0][1]);
          }));
      });

      it('rejects "registration" parameter part of the Request Object', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture2.provider.once(errorEvt, spy);

        return JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: fixture2.code_challenge_method,
          code_challenge: fixture2.code_challenge,
          registration: 'foo',
        }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: fixture2.provider.issuer, expiresIn: 30 }).then((request) => fixture2.wrap({
          agent: fixture2.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
            ((actual) => { assert.ok('message' in Object(actual)); assert.equal(actual.message, 'registration_not_supported'); })(spy.args[0][1]);
          }));
      });

      it('handles unrecognized parameters', { timeout: 3000 }, async () => {
        const client = await fixture2.provider.Client.find('client-with-HS-sig');
        let [key] = client.symmetricKeyStore.selectForSign({ alg: 'HS256' });
        key = await importJWK(key);
        return JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client-with-HS-sig',
          unrecognized: true,
          response_type: 'code',
          scope: 'openid',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: fixture2.code_challenge_method,
          code_challenge: fixture2.code_challenge,
        }, key, 'HS256', { issuer: 'client-with-HS-sig', audience: fixture2.provider.issuer, expiresIn: 30 }).then((request) => fixture2.wrap({
          agent: fixture2.agent,
          route,
          verb,
          auth: {
            request,
            scope: 'openid',
            client_id: 'client-with-HS-sig',
            response_type: 'code',
          },
        })
          .expect(successCode)
          .expect(successFnCheck));
      });
    });
  });
});
