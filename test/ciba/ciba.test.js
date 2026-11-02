import { describe, afterEach, before, it } from 'node:test';
import assert from 'node:assert/strict';
import { createPrivateKey } from 'node:crypto';
import { once } from 'node:events';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import sinon from 'sinon';
import epochTime from '../../lib/helpers/epoch_time.js';
import { AccessDenied } from '../../lib/helpers/errors.js';
import { sign as signJWT } from '../../lib/helpers/jwt.js';
import keys from '../keys.js';
import bootstrap, { assertNoPendingInterceptors, mock } from '../test_helper.js';

import { emitter } from './ciba.config.js';

function errorDetail(spy) {
  return spy.args[0][1].error_detail;
}

describe('features.ciba', () => {
  const fixture = {};

  afterEach(() => assertNoPendingInterceptors(), { timeout: 3000 });
  describe('w/o request objects', () => {
    const fixture1 = Object.create(fixture);

    before(bootstrap(import.meta.url, fixture1), { timeout: 3000 });

    it('extends discovery', { timeout: 3000 }, () => fixture1.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect((response) => {
          ((actual) => { assert.ok('backchannel_authentication_endpoint' in Object(actual)); assert.match(actual.backchannel_authentication_endpoint, /\/backchannel$/); })(response.body);
          assert.ok(!('backchannel_authentication_request_signing_alg_values_supported' in Object(response.body)));
          ((actual) => { assert.ok('backchannel_token_delivery_modes_supported' in Object(actual)); assert.deepEqual(actual.backchannel_token_delivery_modes_supported, ['poll', 'ping']); })(response.body);
          ((actual) => { assert.ok('backchannel_user_code_parameter_supported' in Object(actual)); assert.equal(actual.backchannel_user_code_parameter_supported, true); })(response.body);
        }));

    describe('Provider.prototype.backchannelResult', () => {
      const fixture2 = Object.create(fixture1);

      it('"request" can be a string (BackchannelAuthenticationRequest jti)', { timeout: 3000 }, async () => {
        const result = new AccessDenied();
        const request = new fixture2.provider.BackchannelAuthenticationRequest({ clientId: 'client' });
        await request.save();
        await fixture2.provider.backchannelResult(request.jti, result);
        return assert.rejects(fixture2.provider.backchannelResult('notfound', result), { name: 'Error', message: 'BackchannelAuthenticationRequest not found' });
      });

      it('"request" can be a BackchannelAuthenticationRequest instance', { timeout: 3000 }, async () => {
        const result = new fixture2.provider.Grant({ clientId: 'client', accountId: 'accountId' });
        const request = new fixture2.provider.BackchannelAuthenticationRequest({ clientId: 'client', accountId: 'accountId' });
        await request.save();
        return fixture2.provider.backchannelResult(request, result);
      });

      it('"request" must be a supported type', { timeout: 3000 }, async () => {
        const result = new AccessDenied();

        for (const request of [{}, [], 0, 1, true, false, new Set(), new Error()]) {
          await assert.rejects(fixture2.provider.backchannelResult(request, result), { name: 'TypeError', message: 'invalid "request" argument' });
        }
      });

      it('"result" can be a string (Grant jti)', { timeout: 3000 }, async () => {
        const result = new fixture2.provider.Grant({ clientId: 'client', accountId: 'accountId' });
        const request = new fixture2.provider.BackchannelAuthenticationRequest({ clientId: 'client', accountId: 'accountId' });
        await result.save();
        await fixture2.provider.backchannelResult(request, result.jti);
        return assert.rejects(fixture2.provider.backchannelResult(request, 'notfound'), { name: 'Error', message: 'Grant not found' });
      });

      it('"result" must be a supported type', { timeout: 3000 }, async () => {
        const request = new fixture2.provider.BackchannelAuthenticationRequest({ clientId: 'client' });

        for (const result of [{}, [], 0, 1, true, false, new Set(), new Error()]) {
          await assert.rejects(fixture2.provider.backchannelResult(request, result), { name: 'TypeError', message: 'invalid "result" argument' });
        }
      });

      it('request.clientId must be a valid client', { timeout: 3000 }, async () => {
        const result = new AccessDenied();
        const request = new fixture2.provider.BackchannelAuthenticationRequest({ clientId: 'notfound' });
        return assert.rejects(fixture2.provider.backchannelResult(request, result), { name: 'Error', message: 'Client not found' });
      });

      it('request.clientId must match result.clientId', { timeout: 3000 }, async () => {
        const result = new fixture2.provider.Grant({ clientId: 'client', accountId: 'accountId' });
        const request = new fixture2.provider.BackchannelAuthenticationRequest({ clientId: 'client-ping', accountId: 'accountId' });
        return assert.rejects(fixture2.provider.backchannelResult(request, result), { name: 'Error', message: 'client mismatch' });
      });

      it('request.accountId must match result.accountId', { timeout: 3000 }, async () => {
        const result = new fixture2.provider.Grant({ clientId: 'client', accountId: 'accountId' });
        const request = new fixture2.provider.BackchannelAuthenticationRequest({ clientId: 'client', accountId: 'accountId-2' });
        return assert.rejects(fixture2.provider.backchannelResult(request, result), { name: 'Error', message: 'accountId mismatch' });
      });

      it('saves the "request"', { timeout: 3000 }, async () => {
        const result = new fixture2.provider.Grant({ clientId: 'client', accountId: 'accountId' });
        const request = new fixture2.provider.BackchannelAuthenticationRequest({ clientId: 'client', accountId: 'accountId' });
        assert.ok(!(request.jti));
        await fixture2.provider.backchannelResult(request, result);
        assert.ok(request.jti);
      });

      it('pings the client (204)', { timeout: 3000 }, async () => {
        const result = new fixture2.provider.Grant({ clientId: 'client-ping', accountId: 'accountId' });
        const request = new fixture2.provider.BackchannelAuthenticationRequest({ clientId: 'client-ping', accountId: 'accountId', params: { client_notification_token: 'foo' } });
        mock('https://rp.example.com')
          .intercept({
            path: '/ping',
            method: 'POST',
          })
          .reply(204);
        await fixture2.provider.backchannelResult(request, result);
      });

      it('pings the client (200)', { timeout: 3000 }, async () => {
        const result = new fixture2.provider.Grant({ clientId: 'client-ping', accountId: 'accountId' });
        const request = new fixture2.provider.BackchannelAuthenticationRequest({ clientId: 'client-ping', accountId: 'accountId', params: { client_notification_token: 'foo' } });
        mock('https://rp.example.com')
          .intercept({
            path: '/ping',
            method: 'POST',
          })
          .reply(200);
        await fixture2.provider.backchannelResult(request, result);
      });

      it('pings the client (400)', { timeout: 3000 }, async () => {
        const result = new fixture2.provider.Grant({ clientId: 'client-ping', accountId: 'accountId' });
        const request = new fixture2.provider.BackchannelAuthenticationRequest({ clientId: 'client-ping', accountId: 'accountId', params: { client_notification_token: 'foo' } });
        mock('https://rp.example.com')
          .intercept({
            path: '/ping',
            method: 'POST',
          })
          .reply(400);
        return assert.rejects(fixture2.provider.backchannelResult(request, result), { name: 'Error', message: 'expected 204 No Content from https://rp.example.com/ping, got: 400 Bad Request' });
      });
    });

    describe('backchannel_authentication_endpoint', () => {
      const fixture3 = Object.create(fixture1);

      const route = '/backchannel';

      it('minimal w/ login_hint', { timeout: 3000 }, async () => {
        const [, [, request, account, client], , , , verifyUserCode] = await Promise.all([
          fixture3.agent.post(route)
            .send({
              scope: 'openid',
              login_hint: 'accountId',
              client_id: 'client',
              extra: 'provided',
              unrecognized: true,
            })
            .type('form')
            .expect(200)
            .expect('content-type', /application\/json/)
            .expect((response) => {
              assert.deepEqual(new Set(Object.keys(response.body)), new Set(['expires_in', 'auth_req_id']));
              ((actual) => { assert.equal(typeof actual, 'number'); ((value) => { assert.equal(typeof value, 'number'); assert.ok(value <= 600); })(actual); })(response.body.expires_in);
              assert.equal(typeof response.body.auth_req_id, 'string');
            }),
          once(emitter, 'triggerAuthenticationDevice'),
          once(emitter, 'processLoginHint'),
          once(emitter, 'validateBindingMessage'),
          once(emitter, 'validateRequestContext'),
          once(emitter, 'verifyUserCode'),
        ]);

        assert.deepEqual(request.accountId, account.accountId);
        assert.deepEqual(request.clientId, client.clientId);
        assert.equal(request.resource, undefined);
        assert.deepEqual(request.claims, {});
        assert.equal(request.nonce, undefined);
        assert.deepEqual(request.scope, 'openid');
        assert.deepEqual(request.params, {
          client_id: 'client', login_hint: 'accountId', scope: 'openid', extra2: 'defaulted', extra: 'provided',
        });
        assert.equal(verifyUserCode[1], account);
        assert.equal(verifyUserCode[2], undefined);
      });

      it('does not require PAR for clients with require_pushed_authorization_requests', { timeout: 3000 }, async () => fixture3.agent.post(route)
          .send({
            scope: 'openid',
            login_hint: 'accountId',
            client_id: 'client-par-required',
          })
          .type('form')
          .expect(200)
          .expect('content-type', /application\/json/)
          .expect((response) => {
            assert.deepEqual(new Set(Object.keys(response.body)), new Set(['expires_in', 'auth_req_id']));
          }));

      it('passes user_code to verifyUserCode', { timeout: 3000 }, async () => {
        const [, verifyUserCode] = await Promise.all([
          fixture3.agent.post(route)
            .send({
              scope: 'openid',
              login_hint: 'accountId',
              user_code: '1234',
              client_id: 'client-user-code',
            })
            .type('form')
            .expect(200)
            .expect('content-type', /application\/json/),
          once(emitter, 'verifyUserCode'),
        ]);

        assert.equal(verifyUserCode[2], '1234');
      });

      it('ignores client_notification_token when using poll', { timeout: 3000 }, async () => {
        const [, [, request]] = await Promise.all([
          fixture3.agent.post(route)
            .send({
              scope: 'openid',
              login_hint: 'accountId',
              client_id: 'client',
              client_notification_token: 'foo bar',
            })
            .type('form')
            .expect(200)
            .expect('content-type', /application\/json/),
          once(emitter, 'triggerAuthenticationDevice'),
        ]);

        assert.ok(!('client_notification_token' in Object(request.params)));
      });

      it('requested_expiry', { timeout: 3000 }, async () => {
        await fixture3.agent.post(route)
          .send({
            scope: 'openid',
            login_hint: 'accountId',
            client_id: 'client',
            requested_expiry: 300,
          })
          .type('form')
          .expect(200)
          .expect('content-type', /application\/json/)
          .expect((response) => {
            ((actual) => { assert.equal(typeof actual, 'number'); ((value) => { assert.equal(typeof value, 'number'); assert.ok(value <= 300); })(actual); })(response.body.expires_in);
          });
      });

      it('minimal w/ login_hint_token', { timeout: 3000 }, async () => {
        const [, [, request, account, client]] = await Promise.all([
          fixture3.agent.post(route)
            .send({
              scope: 'openid',
              login_hint_token: 'accountId',
              client_id: 'client',
              unrecognized: true,
            })
            .type('form')
            .expect(200)
            .expect('content-type', /application\/json/)
            .expect((response) => {
              assert.deepEqual(new Set(Object.keys(response.body)), new Set(['expires_in', 'auth_req_id']));
              assert.equal(typeof response.body.expires_in, 'number');
              assert.equal(typeof response.body.auth_req_id, 'string');
            }),
          once(emitter, 'triggerAuthenticationDevice'),
          once(emitter, 'processLoginHintToken'),
          once(emitter, 'validateBindingMessage'),
          once(emitter, 'validateRequestContext'),
          once(emitter, 'verifyUserCode'),
        ]);

        assert.deepEqual(request.accountId, account.accountId);
        assert.deepEqual(request.clientId, client.clientId);
        assert.equal(request.resource, undefined);
        assert.deepEqual(request.claims, {});
        assert.equal(request.nonce, undefined);
        assert.deepEqual(request.scope, 'openid');
        assert.deepEqual(request.params, { client_id: 'client', login_hint_token: 'accountId', scope: 'openid' });
      });

      it('minimal w/ id_token_hint', { timeout: 3000 }, async () => {
        const [, [, request]] = await Promise.all([
          fixture3.agent.post(route)
            .send({
              scope: 'openid',
              login_hint_token: 'accountId',
              client_id: 'client',
              unrecognized: true,
            })
            .type('form')
            .expect(200)
            .expect('content-type', /application\/json/)
            .expect((response) => {
              assert.deepEqual(new Set(Object.keys(response.body)), new Set(['expires_in', 'auth_req_id']));
              assert.equal(typeof response.body.expires_in, 'number');
              assert.equal(typeof response.body.auth_req_id, 'string');
            }),
          once(emitter, 'triggerAuthenticationDevice'),
        ]);
        const grant = new fixture3.provider.Grant({ accountId: 'accountId', clientId: 'client' });
        grant.addOIDCScope('openid');
        await grant.save();
        await fixture3.provider.backchannelResult(request, grant);

        const { body: { id_token } } = await fixture3.agent.post('/token')
          .send({
            client_id: 'client',
            grant_type: 'urn:openid:params:grant-type:ciba',
            auth_req_id: request.jti,
          })
          .type('form')
          .expect(200);

        const [, [, request2, account, client]] = await Promise.all([
          fixture3.agent.post(route)
            .send({
              scope: 'openid',
              id_token_hint: id_token,
              client_id: 'client',
              unrecognized: true,
            })
            .type('form')
            .expect(200)
            .expect('content-type', /application\/json/)
            .expect((response) => {
              assert.deepEqual(new Set(Object.keys(response.body)), new Set(['expires_in', 'auth_req_id']));
              assert.equal(typeof response.body.expires_in, 'number');
              assert.equal(typeof response.body.auth_req_id, 'string');
            }),
          once(emitter, 'triggerAuthenticationDevice'),
          once(emitter, 'validateBindingMessage'),
          once(emitter, 'validateRequestContext'),
          once(emitter, 'verifyUserCode'),
        ]);

        assert.deepEqual(request2.accountId, account.accountId);
        assert.deepEqual(request2.clientId, client.clientId);
        assert.equal(request2.resource, undefined);
        assert.deepEqual(request2.claims, {});
        assert.equal(request2.nonce, undefined);
        assert.deepEqual(request2.scope, 'openid');
        assert.deepEqual(request2.params, { client_id: 'client', id_token_hint: id_token, scope: 'openid' });
      });

      it('rejects an id_token_hint aud array containing a non-string member', { timeout: 3000 }, async () => {
        const idTokenHint = await signJWT({
          aud: ['client', null],
          exp: Math.floor(Date.now() / 1000) + 3600,
          iss: fixture3.provider.issuer,
          sub: 'accountId',
        }, createPrivateKey({ format: 'jwk', key: keys[0] }), 'RS256');

        return fixture3.agent.post(route)
          .send({
            scope: 'openid',
            id_token_hint: idTokenHint,
            client_id: 'client',
          })
          .type('form')
          .expect(400)
          .expect('content-type', /application\/json/)
          .expect({
            error: 'invalid_request',
            error_description: 'could not validate id_token_hint',
          });
      });

      describe('client validation', () => {
        const fixture4 = Object.create(fixture3);

        it('only responds to clients with urn:openid:params:grant-type:ciba enabled', { timeout: 3000 }, () => {
          const spy = sinon.spy();
          fixture4.provider.once('backchannel_authentication.error', spy);

          return fixture4.agent.post(route)
            .send({
              client_id: 'client-not-allowed',
            })
            .type('form')
            .expect(400)
            .expect('content-type', /application\/json/)
            .expect({
              error: 'invalid_request',
              error_description: 'urn:openid:params:grant-type:ciba is not allowed for this client',
            })
            .expect(() => {
              assert.equal(spy.calledOnce, true);
            });
        });

        it('rejects invalid clients', { timeout: 3000 }, () => {
          const spy = sinon.spy();
          fixture4.provider.once('backchannel_authentication.error', spy);

          return fixture4.agent.post(route)
            .send({
              client_id: 'not-found-client',
            })
            .type('form')
            .expect(401)
            .expect('content-type', /application\/json/)
            .expect(() => {
              assert.equal(spy.calledOnce, true);
            })
            .expect({
              error: 'invalid_client',
              error_description: 'client authentication failed',
            });
        });
      });

      it('rejects other than application/x-www-form-urlencoded', { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture3.provider.once('backchannel_authentication.error', spy);

        return fixture3.agent.post(route)
          .send({
            client_id: 'client',
          })
          .expect(400)
          .expect('content-type', /application\/json/)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
          })
          .expect({
            error: 'invalid_request',
            error_description: 'only application/x-www-form-urlencoded content-type bodies are supported on POST /backchannel',
          });
      });

      describe('param validation', () => {
        const fixture5 = Object.create(fixture3);

        ['request', 'request_uri', 'registration'].forEach((param) => {
          it(`check for not supported parameter ${param}`, { timeout: 3000 }, () => {
            const spy = sinon.spy();
            fixture5.provider.once('backchannel_authentication.error', spy);

            return fixture5.agent.post(route)
              .send({
                client_id: 'client',
                scope: 'openid',
                [param]: 'some',
              })
              .type('form')
              .expect(400)
              .expect('content-type', /application\/json/)
              .expect(() => {
                assert.equal(spy.calledOnce, true);
              })
              .expect({
                error: `${param}_not_supported`,
              });
          });
        });

        it('could not resolve Account', { timeout: 3000 }, async () => {
          const spy = sinon.spy();
          fixture5.provider.once('backchannel_authentication.error', spy);

          return fixture5.agent.post(route)
            .send({
              scope: 'openid',
              login_hint: 'notfound',
              client_id: 'client',
            })
            .type('form')
            .expect(400)
            .expect('content-type', /application\/json/)
            .expect(() => {
              assert.equal(spy.calledOnce, true);
            })
            .expect({
              error: 'unknown_user_id',
              error_description: 'could not identify end-user',
            });
        });

        it('could not resolve account identifier', { timeout: 3000 }, async () => {
          const spy = sinon.spy();
          fixture5.provider.once('backchannel_authentication.error', spy);

          return fixture5.agent.post(route)
            .send({
              scope: 'openid',
              login_hint_token: 'notfound',
              client_id: 'client',
            })
            .type('form')
            .expect(400)
            .expect('content-type', /application\/json/)
            .expect(() => {
              assert.equal(spy.calledOnce, true);
            })
            .expect({
              error: 'unknown_user_id',
              error_description: 'could not identify end-user',
            });
        });

        it('requires the scope param', { timeout: 3000 }, async () => {
          const spy = sinon.spy();
          fixture5.provider.once('backchannel_authentication.error', spy);

          return fixture5.agent.post(route)
            .send({
              client_id: 'client',
            })
            .type('form')
            .expect(400)
            .expect('content-type', /application\/json/)
            .expect(() => {
              assert.equal(spy.calledOnce, true);
            })
            .expect({
              error: 'invalid_request',
              error_description: "missing required parameter 'scope'",
            });
        });

        it('requires the client_notification_token param when using ping', { timeout: 3000 }, async () => {
          const spy = sinon.spy();
          fixture5.provider.once('backchannel_authentication.error', spy);

          return fixture5.agent.post(route)
            .send({
              client_id: 'client-ping',
              scope: 'openid',
            })
            .type('form')
            .expect(400)
            .expect('content-type', /application\/json/)
            .expect(() => {
              assert.equal(spy.calledOnce, true);
            })
            .expect({
              error: 'invalid_request',
              error_description: "missing required parameter 'client_notification_token'",
            });
        });

        it('accepts the client_notification_token Bearer token syntax when using ping', { timeout: 3000 }, async () => fixture5.agent.post(route)
            .send({
              client_id: 'client-ping',
              scope: 'openid',
              login_hint: 'accountId',
              client_notification_token: 'abc-._~+/==',
            })
            .type('form')
            .expect(200)
            .expect('content-type', /application\/json/));

        it('validates the client_notification_token syntax when using ping', { timeout: 3000 }, async () => {
          const values = [
            'foo bar',
            'foo:bar',
            'foo=bar',
            'foo,bar',
          ];

          for (const client_notification_token of values) {
            await fixture5.agent.post(route)
              .send({
                client_id: 'client-ping',
                scope: 'openid',
                login_hint: 'accountId',
                client_notification_token,
              })
              .type('form')
              .expect(400)
              .expect('content-type', /application\/json/)
              .expect({
                error: 'invalid_request',
                error_description: 'client_notification_token must be a valid Bearer token',
              });
          }
        });

        it('validates the client_notification_token length when using ping', { timeout: 3000 }, async () => fixture5.agent.post(route)
            .send({
              client_id: 'client-ping',
              scope: 'openid',
              login_hint: 'accountId',
              client_notification_token: 'a'.repeat(1025),
            })
            .type('form')
            .expect(400)
            .expect('content-type', /application\/json/)
            .expect({
              error: 'invalid_request',
              error_description: 'client_notification_token must not exceed 1024 characters',
            }));

        it('requires the scope param with openid', { timeout: 3000 }, async () => {
          const spy = sinon.spy();
          fixture5.provider.once('backchannel_authentication.error', spy);

          return fixture5.agent.post(route)
            .send({
              client_id: 'client',
              scope: 'foo',
            })
            .type('form')
            .expect(400)
            .expect('content-type', /application\/json/)
            .expect(() => {
              assert.equal(spy.calledOnce, true);
            })
            .expect({
              error: 'invalid_request',
              error_description: 'openid scope must be requested for this request',
            });
        });

        it('validates requested_expiry', { timeout: 3000 }, async () => {
          const spy = sinon.spy();
          fixture5.provider.once('backchannel_authentication.error', spy);

          return fixture5.agent.post(route)
            .send({
              client_id: 'client',
              scope: 'openid',
              requested_expiry: 0,
            })
            .type('form')
            .expect(400)
            .expect('content-type', /application\/json/)
            .expect(() => {
              assert.equal(spy.calledOnce, true);
            })
            .expect({
              error: 'invalid_request',
              error_description: 'invalid requested_expiry parameter value',
            });
        });

        it('validates one of the hints is provided', { timeout: 3000 }, async () => {
          const spy = sinon.spy();
          fixture5.provider.once('backchannel_authentication.error', spy);

          return fixture5.agent.post(route)
            .send({
              client_id: 'client',
              scope: 'openid',
            })
            .type('form')
            .expect(400)
            .expect('content-type', /application\/json/)
            .expect(() => {
              assert.equal(spy.calledOnce, true);
            })
            .expect({
              error: 'invalid_request',
              error_description: 'missing one of required parameters login_hint_token, id_token_hint, or login_hint',
            });
        });

        it('validates exactly one of the hints is provided', { timeout: 3000 }, async () => {
          const spy = sinon.spy();
          fixture5.provider.once('backchannel_authentication.error', spy);

          return fixture5.agent.post(route)
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
              assert.equal(spy.calledOnce, true);
            })
            .expect({
              error: 'invalid_request',
              error_description: 'only one of required parameters login_hint_token, id_token_hint, or login_hint must be provided',
            });
        });

        it('request_not_supported', { timeout: 3000 }, async () => {
          const spy = sinon.spy();
          fixture5.provider.once('backchannel_authentication.error', spy);

          return fixture5.agent.post(route)
            .send({
              client_id: 'client',
              request: 'this.should.be.a.jwt',
            })
            .type('form')
            .expect(400)
            .expect('content-type', /application\/json/)
            .expect(() => {
              assert.equal(spy.calledOnce, true);
            })
            .expect({
              error: 'request_not_supported',
            });
        });
      });
    });

    describe('grant_type=urn:openid:params:grant-type:ciba', () => {
      const fixture6 = Object.create(fixture1);

      const grant_type = 'urn:openid:params:grant-type:ciba';

      it('validates the backchannel authentication request is found', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture6.provider.once('grant.error', spy);

        await fixture6.agent.post('/token')
          .send({
            client_id: 'client',
            auth_req_id: 'notfound',
            grant_type,
          })
          .type('form')
          .expect(400)
          .expect((response) => {
            ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
          });

        assert.equal(spy.calledOnce, true);
        assert.equal(errorDetail(spy), 'backchannel authentication request not found');
      });

      it('validates the backchannel authentication request belongs to the client', { timeout: 3000 }, async () => {
        const request = new fixture6.provider.BackchannelAuthenticationRequest({
          clientId: 'client-ping',
          grantId: 'grant',
        });
        const authReqId = await request.save();
        const spy = sinon.spy();
        fixture6.provider.once('grant.error', spy);

        await fixture6.agent.post('/token')
          .send({
            client_id: 'client',
            auth_req_id: authReqId,
            grant_type,
          })
          .type('form')
          .expect(400)
          .expect((response) => {
            ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
          });

        assert.equal(spy.calledOnce, true);
        assert.equal(errorDetail(spy), 'client mismatch');
      });

      it('validates the backchannel authentication request is not expired', { timeout: 3000 }, async () => {
        const request = new fixture6.provider.BackchannelAuthenticationRequest({
          clientId: 'client',
          exp: epochTime() - 1,
          grantId: 'grant',
        });
        const authReqId = await request.save();
        const spy = sinon.spy();
        fixture6.provider.once('grant.error', spy);

        await fixture6.agent.post('/token')
          .send({
            client_id: 'client',
            auth_req_id: authReqId,
            grant_type,
          })
          .type('form')
          .expect(400)
          .expect({
            error: 'expired_token',
            error_description: 'backchannel authentication request is expired',
        });

        assert.equal(spy.calledOnce, true);
        ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'backchannel authentication request is expired'); })(spy.args[0][1]);
      });

      it('revokes the grant when the request was already consumed', { timeout: 3000 }, async () => {
        const grant = new fixture6.provider.Grant({
          accountId: 'accountId',
          clientId: 'client',
        });
        const grantId = await grant.save();
        const request = new fixture6.provider.BackchannelAuthenticationRequest({
          accountId: 'accountId',
          clientId: 'client',
          grantId,
        });
        const authReqId = await request.save();
        await request.consume();

        const grantErrorSpy = sinon.spy();
        const grantRevokeSpy = sinon.spy();
        fixture6.provider.once('grant.error', grantErrorSpy);
        fixture6.provider.once('grant.revoked', grantRevokeSpy);

        await fixture6.agent.post('/token')
          .send({
            client_id: 'client',
            auth_req_id: authReqId,
            grant_type,
          })
          .type('form')
          .expect(400)
          .expect((response) => {
            ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
          });

        assert.equal(grantErrorSpy.calledOnce, true);
        assert.equal(errorDetail(grantErrorSpy), 'backchannel authentication request already consumed');
        assert.equal(grantRevokeSpy.calledOnceWithExactly(grantErrorSpy.args[0][0], grantId), true);
        assert.equal(await fixture6.provider.Grant.find(grantId), undefined);
        assert.equal(await fixture6.provider.BackchannelAuthenticationRequest.find(authReqId), undefined);
      });

      it('skips grant revocation when an already consumed request has no grantId', { timeout: 3000 }, async () => {
        const request = new fixture6.provider.BackchannelAuthenticationRequest({ clientId: 'client' });
        await fixture6.provider.backchannelResult(request, new AccessDenied());

        await fixture6.agent.post('/token')
          .send({
            client_id: 'client',
            auth_req_id: request.jti,
            grant_type,
          })
          .type('form')
          .expect(400)
          .expect((response) => {
            ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'access_denied'); })(response.body);
          });

        const sandbox = sinon.createSandbox();
        try {
          const accessTokenRevokeByGrantIdSpy = sandbox.spy(fixture6.TestAdapter.for('AccessToken'), 'revokeByGrantId');
          const refreshTokenRevokeByGrantIdSpy = sandbox.spy(fixture6.TestAdapter.for('RefreshToken'), 'revokeByGrantId');
          const backchannelRequestRevokeByGrantIdSpy = sandbox.spy(fixture6.TestAdapter.for('BackchannelAuthenticationRequest'), 'revokeByGrantId');
          const grantDestroySpy = sandbox.spy(fixture6.TestAdapter.for('Grant'), 'destroy');
          const grantErrorSpy = sinon.spy();
          const grantRevokeSpy = sinon.spy();
          fixture6.provider.once('grant.error', grantErrorSpy);
          fixture6.provider.once('grant.revoked', grantRevokeSpy);

          await fixture6.agent.post('/token')
            .send({
              client_id: 'client',
              auth_req_id: request.jti,
              grant_type,
            })
            .type('form')
            .expect(400)
            .expect(() => {
              assert.equal(grantErrorSpy.calledOnce, true);
              assert.equal(errorDetail(grantErrorSpy), 'backchannel authentication request already consumed');
              assert.equal(grantRevokeSpy.called, false);
              assert.equal(accessTokenRevokeByGrantIdSpy.called, false);
              assert.equal(refreshTokenRevokeByGrantIdSpy.called, false);
              assert.equal(backchannelRequestRevokeByGrantIdSpy.called, false);
              assert.equal(grantDestroySpy.called, false);
            })
            .expect((response) => {
              ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_grant'); })(response.body);
            });
        } finally {
          sandbox.restore();
        }
      });
    });
  });

  describe('with request objects', () => {
    const fixture7 = Object.create(fixture);

    before(bootstrap(import.meta.url, fixture7, { config: 'ciba_jar' }), { timeout: 3000 });

    it('extends discovery', { timeout: 3000 }, () => fixture7.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect((response) => {
          ((actual) => { assert.ok('backchannel_authentication_request_signing_alg_values_supported' in Object(actual)); assert.ok(!(actual.backchannel_authentication_request_signing_alg_values_supported.includes('HS256'))); })(response.body);
        }));

    describe('backchannel_authentication_endpoint', () => {
      const fixture8 = Object.create(fixture7);

      const route = '/backchannel';

      describe('param validation', () => {
        const fixture9 = Object.create(fixture8);

        ['request_uri', 'registration'].forEach((param) => {
          it(`check for not supported parameter ${param}`, { timeout: 3000 }, () => {
            const spy = sinon.spy();
            fixture9.provider.once('backchannel_authentication.error', spy);

            return fixture9.agent.post(route)
              .send({
                client_id: 'client',
                scope: 'openid',
                [param]: 'some',
              })
              .type('form')
              .expect(400)
              .expect('content-type', /application\/json/)
              .expect(() => {
                assert.equal(spy.calledOnce, true);
              })
              .expect({
                error: `${param}_not_supported`,
              });
          });
        });

        it('validates request object is used', { timeout: 3000 }, async () => {
          const spy = sinon.spy();
          fixture9.provider.once('backchannel_authentication.error', spy);

          await fixture9.agent.post(route)
            .send({
              client_id: 'client-signed',
              scope: 'openid',
            })
            .type('form')
            .expect(400)
            .expect('content-type', /application\/json/)
            .expect(() => {
              assert.equal(spy.calledOnce, true);
            })
            .expect({
              error: 'invalid_request',
              error_description: 'Request Object must be used by this client',
            });

          const { privateKey, publicKey } = await generateKeyPair('ES256');

          mock('https://rp.example.com')
            .intercept({
              path: '/jwks',
            })
            .reply(200, { keys: [await exportJWK(publicKey)] });

          return fixture9.agent.post(route)
            .send({
              client_id: 'client-signed',
              request: await new SignJWT({
                client_id: 'client-signed',
                scope: 'openid',
                login_hint: 'accountId',
              }).setProtectedHeader({ alg: 'ES256' })
                .setJti('foo')
                .setExpirationTime('5m')
                .setNotBefore('0s')
                .setIssuer('client-signed')
                .setIssuedAt()
                .setAudience(fixture9.provider.issuer)
                .sign(privateKey),
            })
            .type('form')
            .expect(200);
        });

        it('validates request object claims are present (exp)', { timeout: 3000 }, async () => {
          const spy = sinon.spy();
          fixture9.provider.once('backchannel_authentication.error', spy);

          const { privateKey } = await generateKeyPair('ES256');

          return fixture9.agent.post(route)
            .send({
              client_id: 'client-signed',
              request: await new SignJWT({
                client_id: 'client-signed',
                scope: 'openid',
                login_hint: 'accountId',
              }).setProtectedHeader({ alg: 'ES256' })
                .setJti('foo')
                // .setExpirationTime('5m')
                .setNotBefore('0s')
                .setIssuer('client-signed')
                .setIssuedAt()
                .setAudience(fixture9.provider.issuer)
                .sign(privateKey),
            })
            .type('form')
            .expect(400)
            .expect('content-type', /application\/json/)
            .expect(() => {
              assert.equal(spy.calledOnce, true);
            })
            .expect({
              error: 'invalid_request',
              error_description: "Request Object is missing the 'exp' claim",
            });
        });

        it('validates request object claims are present (nbf)', { timeout: 3000 }, async () => {
          const spy = sinon.spy();
          fixture9.provider.once('backchannel_authentication.error', spy);

          const { privateKey } = await generateKeyPair('ES256');

          return fixture9.agent.post(route)
            .send({
              client_id: 'client-signed',
              request: await new SignJWT({
                client_id: 'client-signed',
                scope: 'openid',
                login_hint: 'accountId',
              }).setProtectedHeader({ alg: 'ES256' })
                .setJti('foo')
                .setExpirationTime('5m')
                // .setNotBefore('0s')
                .setIssuer('client-signed')
                .setIssuedAt()
                .setAudience(fixture9.provider.issuer)
                .sign(privateKey),
            })
            .type('form')
            .expect(400)
            .expect('content-type', /application\/json/)
            .expect(() => {
              assert.equal(spy.calledOnce, true);
            })
            .expect({
              error: 'invalid_request',
              error_description: "Request Object is missing the 'nbf' claim",
            });
        });

        it('validates request object claims are present (jti)', { timeout: 3000 }, async () => {
          const spy = sinon.spy();
          fixture9.provider.once('backchannel_authentication.error', spy);

          const { privateKey } = await generateKeyPair('ES256');

          return fixture9.agent.post(route)
            .send({
              client_id: 'client-signed',
              request: await new SignJWT({
                client_id: 'client-signed',
                scope: 'openid',
                login_hint: 'accountId',
              }).setProtectedHeader({ alg: 'ES256' })
                // .setJti('foo')
                .setExpirationTime('5m')
                .setNotBefore('0s')
                .setIssuer('client-signed')
                .setIssuedAt()
                .setAudience(fixture9.provider.issuer)
                .sign(privateKey),
            })
            .type('form')
            .expect(400)
            .expect('content-type', /application\/json/)
            .expect(() => {
              assert.equal(spy.calledOnce, true);
            })
            .expect({
              error: 'invalid_request',
              error_description: "Request Object is missing the 'jti' claim",
            });
        });

        it('validates request object claims are present (iat)', { timeout: 3000 }, async () => {
          const spy = sinon.spy();
          fixture9.provider.once('backchannel_authentication.error', spy);

          const { privateKey } = await generateKeyPair('ES256');

          return fixture9.agent.post(route)
            .send({
              client_id: 'client-signed',
              request: await new SignJWT({
                client_id: 'client-signed',
                scope: 'openid',
                login_hint: 'accountId',
              }).setProtectedHeader({ alg: 'ES256' })
                .setJti('foo')
                .setExpirationTime('5m')
                .setNotBefore('0s')
                .setIssuer('client-signed')
                // .setIssuedAt()
                .setAudience(fixture9.provider.issuer)
                .sign(privateKey),
            })
            .type('form')
            .expect(400)
            .expect('content-type', /application\/json/)
            .expect(() => {
              assert.equal(spy.calledOnce, true);
            })
            .expect({
              error: 'invalid_request',
              error_description: "Request Object is missing the 'iat' claim",
            });
        });

        it('validates Encrypted Request Objects are not used', { timeout: 3000 }, async () => {
          const spy = sinon.spy();
          fixture9.provider.once('backchannel_authentication.error', spy);

          return fixture9.agent.post(route)
            .send({
              client_id: 'client-signed',
              scope: 'openid',
              request: '....',
            })
            .type('form')
            .expect(400)
            .expect('content-type', /application\/json/)
            .expect(() => {
              assert.equal(spy.calledOnce, true);
            })
            .expect({
              error: 'invalid_request',
              error_description: 'Encrypted Request Objects are not supported by CIBA',
            });
        });
      });
    });
  });
});
