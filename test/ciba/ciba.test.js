import { strict as assert } from 'node:assert';
import { once } from 'node:events';

import sinon from 'sinon';
import { expect } from 'chai';
import { generateKeyPair, SignJWT, exportJWK } from 'jose';

import { AccessDenied } from '../../lib/helpers/errors.js';
import bootstrap, { assertNoPendingInterceptors, mock } from '../test_helper.js';

import { emitter } from './ciba.config.js';

describe('features.ciba', () => {
  afterEach(assertNoPendingInterceptors);
  context('w/o request objects', () => {
    before(bootstrap(import.meta.url));

    it('extends discovery', function () {
      return this.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('backchannel_authentication_endpoint').matches(/\/backchannel$/);
          expect(response.body).not.to.have.property('backchannel_authentication_request_signing_alg_values_supported');
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

        for (const request of [{}, [], 0, 1, true, false, new Set(), new Error()]) {
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

        for (const result of [{}, [], 0, 1, true, false, new Set(), new Error()]) {
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
        mock('https://rp.example.com')
          .intercept({
            path: '/ping',
            method: 'POST',
          })
          .reply(204);
        await this.provider.backchannelResult(request, result);
      });

      it('pings the client (200)', async function () {
        const result = new this.provider.Grant({ clientId: 'client-ping', accountId: 'accountId' });
        const request = new this.provider.BackchannelAuthenticationRequest({ clientId: 'client-ping', accountId: 'accountId', params: { client_notification_token: 'foo' } });
        mock('https://rp.example.com')
          .intercept({
            path: '/ping',
            method: 'POST',
          })
          .reply(200);
        await this.provider.backchannelResult(request, result);
      });

      it('pings the client (400)', async function () {
        const result = new this.provider.Grant({ clientId: 'client-ping', accountId: 'accountId' });
        const request = new this.provider.BackchannelAuthenticationRequest({ clientId: 'client-ping', accountId: 'accountId', params: { client_notification_token: 'foo' } });
        mock('https://rp.example.com')
          .intercept({
            path: '/ping',
            method: 'POST',
          })
          .reply(400);
        return assert.rejects(this.provider.backchannelResult(request, result), { name: 'Error', message: 'expected 204 No Content from https://rp.example.com/ping, got: 400 Bad Request' });
      });
    });

    describe('backchannel_authentication_endpoint', () => {
      const route = '/backchannel';

      it('minimal w/ login_hint', async function () {
        const [, [, request, account, client]] = await Promise.all([
          this.agent.post(route)
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
              expect(response.body).to.have.keys('expires_in', 'auth_req_id');
              expect(response.body.expires_in).to.be.a('number').most(600);
              expect(response.body.auth_req_id).to.be.a('string');
            }),
          once(emitter, 'triggerAuthenticationDevice'),
          once(emitter, 'processLoginHint'),
          once(emitter, 'validateBindingMessage'),
          once(emitter, 'validateRequestContext'),
          once(emitter, 'verifyUserCode'),
        ]);

        expect(request.accountId).to.eql(account.accountId);
        expect(request.clientId).to.eql(client.clientId);
        expect(request.resource).to.be.undefined;
        expect(request.claims).to.deep.eql({});
        expect(request.nonce).to.be.undefined;
        expect(request.scope).to.be.eql('openid');
        expect(request.params).to.deep.eql({
          client_id: 'client', login_hint: 'accountId', scope: 'openid', extra2: 'defaulted', extra: 'provided',
        });
      });

      it('requested_expiry', async function () {
        await this.agent.post(route)
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
            expect(response.body.expires_in).to.be.a('number').most(300);
          });
      });

      it('minimal w/ login_hint_token', async function () {
        const [, [, request, account, client]] = await Promise.all([
          this.agent.post(route)
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
              expect(response.body).to.have.keys('expires_in', 'auth_req_id');
              expect(response.body.expires_in).to.be.a('number');
              expect(response.body.auth_req_id).to.be.a('string');
            }),
          once(emitter, 'triggerAuthenticationDevice'),
          once(emitter, 'processLoginHintToken'),
          once(emitter, 'validateBindingMessage'),
          once(emitter, 'validateRequestContext'),
          once(emitter, 'verifyUserCode'),
        ]);

        expect(request.accountId).to.eql(account.accountId);
        expect(request.clientId).to.eql(client.clientId);
        expect(request.resource).to.be.undefined;
        expect(request.claims).to.deep.eql({});
        expect(request.nonce).to.be.undefined;
        expect(request.scope).to.be.eql('openid');
        expect(request.params).to.deep.eql({ client_id: 'client', login_hint_token: 'accountId', scope: 'openid' });
      });

      it('minimal w/ id_token_hint', async function () {
        const [, [, request]] = await Promise.all([
          this.agent.post(route)
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
              expect(response.body).to.have.keys('expires_in', 'auth_req_id');
              expect(response.body.expires_in).to.be.a('number');
              expect(response.body.auth_req_id).to.be.a('string');
            }),
          once(emitter, 'triggerAuthenticationDevice'),
        ]);
        const grant = new this.provider.Grant({ accountId: 'accountId', clientId: 'client' });
        grant.addOIDCScope('openid');
        await grant.save();
        await this.provider.backchannelResult(request, grant);

        const { body: { id_token } } = await this.agent.post('/token')
          .send({
            client_id: 'client',
            grant_type: 'urn:openid:params:grant-type:ciba',
            auth_req_id: request.jti,
          })
          .type('form')
          .expect(200);

        const [, [, request2, account, client]] = await Promise.all([
          this.agent.post(route)
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
              expect(response.body).to.have.keys('expires_in', 'auth_req_id');
              expect(response.body.expires_in).to.be.a('number');
              expect(response.body.auth_req_id).to.be.a('string');
            }),
          once(emitter, 'triggerAuthenticationDevice'),
          once(emitter, 'validateBindingMessage'),
          once(emitter, 'validateRequestContext'),
          once(emitter, 'verifyUserCode'),
        ]);

        expect(request2.accountId).to.eql(account.accountId);
        expect(request2.clientId).to.eql(client.clientId);
        expect(request2.resource).to.be.undefined;
        expect(request2.claims).to.deep.eql({});
        expect(request2.nonce).to.be.undefined;
        expect(request2.scope).to.be.eql('openid');
        expect(request2.params).to.deep.eql({ client_id: 'client', id_token_hint: id_token, scope: 'openid' });
      });

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
              error: 'invalid_request',
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
        ['request', 'request_uri', 'registration'].forEach((param) => {
          it(`check for not supported parameter ${param}`, function () {
            const spy = sinon.spy();
            this.provider.once('backchannel_authentication.error', spy);

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
              });
          });
        });

        it('could not resolve Account', async function () {
          const spy = sinon.spy();
          this.provider.once('backchannel_authentication.error', spy);

          return this.agent.post(route)
            .send({
              scope: 'openid',
              login_hint: 'notfound',
              client_id: 'client',
            })
            .type('form')
            .expect(400)
            .expect('content-type', /application\/json/)
            .expect(() => {
              expect(spy.calledOnce).to.be.true;
            })
            .expect({
              error: 'unknown_user_id',
              error_description: 'could not identify end-user',
            });
        });

        it('could not resolve account identifier', async function () {
          const spy = sinon.spy();
          this.provider.once('backchannel_authentication.error', spy);

          return this.agent.post(route)
            .send({
              scope: 'openid',
              login_hint_token: 'notfound',
              client_id: 'client',
            })
            .type('form')
            .expect(400)
            .expect('content-type', /application\/json/)
            .expect(() => {
              expect(spy.calledOnce).to.be.true;
            })
            .expect({
              error: 'unknown_user_id',
              error_description: 'could not identify end-user',
            });
        });

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

        it('request_not_supported', async function () {
          const spy = sinon.spy();
          this.provider.once('backchannel_authentication.error', spy);

          return this.agent.post(route)
            .send({
              client_id: 'client',
              request: 'this.should.be.a.jwt',
            })
            .type('form')
            .expect(400)
            .expect('content-type', /application\/json/)
            .expect(() => {
              expect(spy.calledOnce).to.be.true;
            })
            .expect({
              error: 'request_not_supported',
            });
        });
      });
    });
  });

  context('with request objects', () => {
    before(bootstrap(import.meta.url, { config: 'ciba_jar' }));

    it('extends discovery', function () {
      return this.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('backchannel_authentication_request_signing_alg_values_supported').not.contains('HS256');
        });
    });

    describe('backchannel_authentication_endpoint', () => {
      const route = '/backchannel';

      describe('param validation', () => {
        ['request_uri', 'registration'].forEach((param) => {
          it(`check for not supported parameter ${param}`, function () {
            const spy = sinon.spy();
            this.provider.once('backchannel_authentication.error', spy);

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
              });
          });
        });

        it('validates request object is used', async function () {
          const spy = sinon.spy();
          this.provider.once('backchannel_authentication.error', spy);

          await this.agent.post(route)
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

          const { privateKey, publicKey } = await generateKeyPair('ES256');

          mock('https://rp.example.com')
            .intercept({
              path: '/jwks',
            })
            .reply(200, { keys: [await exportJWK(publicKey)] });

          return this.agent.post(route)
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
                .setAudience(this.provider.issuer)
                .sign(privateKey),
            })
            .type('form')
            .expect(200);
        });

        it('validates request object claims are present (exp)', async function () {
          const spy = sinon.spy();
          this.provider.once('backchannel_authentication.error', spy);

          const { privateKey } = await generateKeyPair('ES256');

          return this.agent.post(route)
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
                .setAudience(this.provider.issuer)
                .sign(privateKey),
            })
            .type('form')
            .expect(400)
            .expect('content-type', /application\/json/)
            .expect(() => {
              expect(spy.calledOnce).to.be.true;
            })
            .expect({
              error: 'invalid_request',
              error_description: "Request Object is missing the 'exp' claim",
            });
        });

        it('validates request object claims are present (nbf)', async function () {
          const spy = sinon.spy();
          this.provider.once('backchannel_authentication.error', spy);

          const { privateKey } = await generateKeyPair('ES256');

          return this.agent.post(route)
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
                .setAudience(this.provider.issuer)
                .sign(privateKey),
            })
            .type('form')
            .expect(400)
            .expect('content-type', /application\/json/)
            .expect(() => {
              expect(spy.calledOnce).to.be.true;
            })
            .expect({
              error: 'invalid_request',
              error_description: "Request Object is missing the 'nbf' claim",
            });
        });

        it('validates request object claims are present (jti)', async function () {
          const spy = sinon.spy();
          this.provider.once('backchannel_authentication.error', spy);

          const { privateKey } = await generateKeyPair('ES256');

          return this.agent.post(route)
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
                .setAudience(this.provider.issuer)
                .sign(privateKey),
            })
            .type('form')
            .expect(400)
            .expect('content-type', /application\/json/)
            .expect(() => {
              expect(spy.calledOnce).to.be.true;
            })
            .expect({
              error: 'invalid_request',
              error_description: "Request Object is missing the 'jti' claim",
            });
        });

        it('validates request object claims are present (iat)', async function () {
          const spy = sinon.spy();
          this.provider.once('backchannel_authentication.error', spy);

          const { privateKey } = await generateKeyPair('ES256');

          return this.agent.post(route)
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
                .setAudience(this.provider.issuer)
                .sign(privateKey),
            })
            .type('form')
            .expect(400)
            .expect('content-type', /application\/json/)
            .expect(() => {
              expect(spy.calledOnce).to.be.true;
            })
            .expect({
              error: 'invalid_request',
              error_description: "Request Object is missing the 'iat' claim",
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
});
