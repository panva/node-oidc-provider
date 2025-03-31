import * as crypto from 'node:crypto';
import { parse } from 'node:url';

import { importJWK } from 'jose';
import sinon from 'sinon';
import { expect } from 'chai';

import * as JWT from '../../lib/helpers/jwt.js';
import bootstrap from '../test_helper.js';

describe('request parameter features', () => {
  before(bootstrap(import.meta.url));

  describe('configuration features.request', () => {
    it('extends discovery', async function () {
      await this.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('request_parameter_supported', true);
          expect(response.body).not.to.have.property('require_signed_request_object');
        });

      i(this.provider).features.requestObjects.requireSignedRequestObject = true;

      await this.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('request_parameter_supported', true);
          expect(response.body).to.have.property('require_signed_request_object', true);
        });
    });

    after(function () {
      i(this.provider).features.requestObjects.requireSignedRequestObject = false;
    });
  });

  function redirectSuccess(response) {
    const expected = parse('https://client.example.com/cb', true);
    const actual = parse(response.headers.location, true);
    ['protocol', 'host', 'pathname'].forEach((attr) => {
      expect(actual[attr]).to.equal(expected[attr]);
    });
    expect(actual.query).to.have.property('code');
  }
  function httpSuccess({ body }) {
    expect(body).to.contain.key('device_code');
  }

  [
    ['/auth', 'get', 'authorization.error', 303, 303, redirectSuccess, 'authorization.success'],
    ['/auth', 'post', 'authorization.error', 303, 303, redirectSuccess, 'authorization.success'],
    ['/device/auth', 'post', 'device_authorization.error', 200, 400, httpSuccess, 'device_authorization.success'],
  ].forEach(([
    route, verb, errorEvt, successCode, errorCode, successFnCheck, successEvt,
  ]) => {
    describe(`${route} ${verb} passing request parameters as JWTs`, () => {
      before(function () {
        return this.login({
          claims: { id_token: { email: null } },
        });
      });
      after(function () {
        i(this.provider).configuration.clockTolerance = 0;
        return this.logout();
      });
      if (route === '/auth') {
        beforeEach(function () {
          this.code_challenge_method = 'S256';
          this.code_verifier = crypto.randomBytes(32).toString('base64url');
          this.code_challenge = crypto.hash('sha256', this.code_verifier, 'base64url');
        });
      }

      it('does not use anything from the OAuth 2.0 parameters', async function () {
        const spy = sinon.spy();
        this.provider.once('authorization.success', spy);

        if (successCode === 200) {
          this.provider.once('device_authorization.success', ({ oidc }) => {
            this.provider.emit('authorization.success', { oidc: { params: oidc.entities.DeviceCode.params } });
          });
        }

        await JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: this.code_challenge_method,
          code_challenge: this.code_challenge,
          scope: 'openid',
        }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: this.provider.issuer, expiresIn: 30 }).then((request) => this.wrap({
          agent: this.agent,
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
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][0].oidc.params.ui_locales).to.eq(undefined);
          }));
      });

      it('can contain max_age parameter as a number and it (and other params too) will be forced as string', async function () {
        const spy = sinon.spy();
        this.provider.once(successEvt, spy);

        await JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client',
          response_type: 'code',
          scope: 'openid',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: this.code_challenge_method,
          code_challenge: this.code_challenge,
          max_age: 300,
        }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: this.provider.issuer, expiresIn: 30 }).then((request) => this.wrap({
          agent: this.agent,
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

        expect(
          spy.calledWithMatch({ oidc: { params: { max_age: sinon.match.string } } }),
        ).to.be.true;
      });

      it('can contain params as array and have them handled as dupes', async function () {
        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);

        return JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client',
          response_type: 'code',
          scope: ['openid', 'profile'],
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: this.code_challenge_method,
          code_challenge: this.code_challenge,
        }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: this.provider.issuer, expiresIn: 30 }).then((request) => this.wrap({
          agent: this.agent,
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
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][1]).to.have.property('message', 'invalid_request');
            expect(spy.args[0][1]).to.have.property(
              'error_description',
              "'scope' parameter must not be provided twice",
            );
          }));
      });

      it('can contain claims parameter as JSON', async function () {
        const spy = sinon.spy();
        this.provider.once(successEvt, spy);
        const claims = JSON.stringify({ id_token: { email: null } });

        await JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: this.code_challenge_method,
          code_challenge: this.code_challenge,
          scope: 'openid',
          claims,
        }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: this.provider.issuer, expiresIn: 30 }).then((request) => this.wrap({
          agent: this.agent,
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

        expect(
          spy.calledWithMatch({ oidc: { params: { claims } } }),
        ).to.be.true;
      });

      it('can contain claims parameter as object', async function () {
        const spy = sinon.spy();
        this.provider.once(successEvt, spy);
        const claims = { id_token: { email: null } };

        await JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: this.code_challenge_method,
          code_challenge: this.code_challenge,
          claims: { id_token: { email: null } },
          scope: 'openid',
        }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: this.provider.issuer, expiresIn: 30 }).then((request) => this.wrap({
          agent: this.agent,
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

        expect(
          spy.calledWithMatch({ oidc: { params: { claims: JSON.stringify(claims) } } }),
        ).to.be.true;
      });

      it('can accept Request Objects issued within acceptable system clock skew', async function () {
        const client = await this.provider.Client.find('client-with-HS-sig');
        let [key] = client.symmetricKeyStore.selectForSign({ alg: 'HS256' });
        key = await importJWK(key);
        i(this.provider).configuration.clockTolerance = 10;
        return JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          iat: Math.ceil(Date.now() / 1000) + 5,
          client_id: 'client-with-HS-sig',
          scope: 'openid',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: this.code_challenge_method,
          code_challenge: this.code_challenge,
        }, key, 'HS256', { issuer: 'client-with-HS-sig', audience: this.provider.issuer, expiresIn: 30 }).then((request) => this.wrap({
          agent: this.agent,
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

      it('works with signed by an actual DSA', async function () {
        const client = await this.provider.Client.find('client-with-HS-sig');
        let [key] = client.symmetricKeyStore.selectForSign({ alg: 'HS256' });
        key = await importJWK(key);
        return JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client-with-HS-sig',
          scope: 'openid',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: this.code_challenge_method,
          code_challenge: this.code_challenge,
        }, key, 'HS256', { issuer: 'client-with-HS-sig', audience: this.provider.issuer, expiresIn: 30 }).then((request) => this.wrap({
          agent: this.agent,
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

      it('rejects HMAC based requests when signed with an expired secret', async function () {
        const client = await this.provider.Client.find('client-with-HS-sig-expired');
        let [key] = client.symmetricKeyStore.selectForSign({ alg: 'HS256' });
        key = await importJWK(key);

        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);

        return JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client-with-HS-sig-expired',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: this.code_challenge_method,
          code_challenge: this.code_challenge,
        }, key, 'HS256', { issuer: 'client-with-HS-sig-expired', audience: this.provider.issuer, expiresIn: 30 }).then((request) => this.wrap({
          agent: this.agent,
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
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][1]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][1]).to.have.property(
              'error_description',
              'could not validate the Request Object - the client secret used for its signature is expired',
            );
          }));
      });

      it('doesnt allow request inception', function () {
        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);

        return JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client',
          response_type: 'code',
          request: 'request inception',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: this.code_challenge_method,
          code_challenge: this.code_challenge,
        }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: this.provider.issuer, expiresIn: 30 }).then((request) => this.wrap({
          agent: this.agent,
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
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][1]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][1]).to.have.property(
              'error_description',
              'Request Object must not contain request or request_uri properties',
            );
          }));
      });

      it('doesnt allow requestUri inception', function () {
        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);

        return JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client',
          response_type: 'code',
          request_uri: 'request uri inception',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: this.code_challenge_method,
          code_challenge: this.code_challenge,
        }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: this.provider.issuer, expiresIn: 30 }).then((request) => this.wrap({
          agent: this.agent,
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
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][1]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][1]).to.have.property(
              'error_description',
              'Request Object must not contain request or request_uri properties',
            );
          }));
      });

      if (route !== '/device/auth') {
        it('may contain a response_mode and it will be honoured', function () {
          return JWT.sign({
            jti: crypto.randomBytes(16).toString('base64url'),
            client_id: 'client',
            response_type: 'code',
            response_mode: 'fragment',
            scope: 'openid',
            redirect_uri: 'https://client.example.com/cb',
            code_challenge_method: this.code_challenge_method,
            code_challenge: this.code_challenge,
          }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: this.provider.issuer, expiresIn: 30 }).then((request) => this.wrap({
            agent: this.agent,
            route,
            verb,
            auth: {
              request,
              scope: 'openid',
              client_id: 'client',
              response_type: 'code',
            },
          })
            .expect(this.AuthorizationRequest.prototype.validateFragment)
            .expect(successCode)
            .expect(successFnCheck));
        });

        it('checks the response mode from the request', function () {
          const spy = sinon.spy();
          this.provider.once(errorEvt, spy);

          return JWT.sign({
            jti: crypto.randomBytes(16).toString('base64url'),
            client_id: 'client',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
            code_challenge_method: this.code_challenge_method,
            code_challenge: this.code_challenge,
            response_mode: 'foo',
          }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: this.provider.issuer, expiresIn: 30 }).then((request) => this.wrap({
            agent: this.agent,
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
              expect(spy.calledOnce).to.be.true;
              expect(spy.args[0][1]).to.have.property('message', 'unsupported_response_mode');
              expect(spy.args[0][1]).to.have.property(
                'error_description',
                'unsupported response_mode requested',
              );
            }));
        });

        it('doesnt allow response_type to differ', function () {
          const spy = sinon.spy();
          this.provider.once(errorEvt, spy);

          return JWT.sign({
            jti: crypto.randomBytes(16).toString('base64url'),
            client_id: 'client',
            response_type: 'id_token',
            redirect_uri: 'https://client.example.com/cb',
            code_challenge_method: this.code_challenge_method,
            code_challenge: this.code_challenge,
          }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: this.provider.issuer, expiresIn: 30 }).then((request) => this.wrap({
            agent: this.agent,
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
              expect(spy.calledOnce).to.be.true;
              expect(spy.args[0][1]).to.have.property('message', 'invalid_request_object');
              expect(spy.args[0][1]).to.have.property(
                'error_description',
                'request response_type must equal the one in request parameters',
              );
            }));
        });

        it('uses the state from the request even if its validations will fail', function () {
          const spy = sinon.spy();
          this.provider.once(errorEvt, spy);

          return JWT.sign({
            jti: crypto.randomBytes(16).toString('base64url'),
            client_id: 'client2',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
            code_challenge_method: this.code_challenge_method,
            code_challenge: this.code_challenge,
            state: 'foobar',
          }, Buffer.from('secret'), 'HS256', { issuer: 'client2', audience: this.provider.issuer, expiresIn: 30 }).then((request) => this.wrap({
            agent: this.agent,
            route,
            verb,
            auth: {
              request,
              scope: 'openid',
              client_id: 'client',
              response_type: 'code',
            },
          })
            .expect(this.AuthorizationRequest.prototype.validateResponseParameter.call({}, 'state', 'foobar'))
            .expect(errorCode)
            .expect(() => {
              expect(spy.calledOnce).to.be.true;
              expect(spy.args[0][1]).to.have.property('message', 'invalid_request_object');
              expect(spy.args[0][1]).to.have.property(
                'error_description',
                'request client_id must equal the one in request parameters',
              );
            }));
        });
      }

      it('doesnt allow client_id to differ', function () {
        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);

        return JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client2',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: this.code_challenge_method,
          code_challenge: this.code_challenge,
        }, Buffer.from('secret'), 'HS256', { issuer: 'client2', audience: this.provider.issuer, expiresIn: 30 }).then((request) => this.wrap({
          agent: this.agent,
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
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][1]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][1]).to.have.property(
              'error_description',
              'request client_id must equal the one in request parameters',
            );
          }));
      });

      it('handles invalid signed looklike jwts', function () {
        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);

        return this.wrap({
          agent: this.agent,
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
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][1]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][1]).to.have.property('error_description').and.matches(/could not parse Request Object/);
          });
      });

      it('doesnt allow clients with predefined alg to bypass this alg', function () {
        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);

        return JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client-with-HS-sig',
          scope: 'openid',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: this.code_challenge_method,
          code_challenge: this.code_challenge,
        }, Buffer.from('secret'), 'HS512', { issuer: 'client-with-HS-sig', audience: this.provider.issuer, expiresIn: 30 }).then((request) => this.wrap({
          agent: this.agent,
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
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][1]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][1]).to.have.property(
              'error_description',
              'the preregistered alg must be used in request or request_uri',
            );
          }));
      });

      it('unsupported algs must not be used', async function () {
        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);

        return JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: this.code_challenge_method,
          code_challenge: this.code_challenge,
        }, crypto.createSecretKey(crypto.randomBytes(48)), 'HS384', { issuer: 'client', audience: this.provider.issuer, expiresIn: 30 }).then((request) => this.wrap({
          agent: this.agent,
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
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][1]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][1]).to.have.property('error_description', 'unsupported signed request alg');
          }));
      });

      it('bad signatures will be rejected', async function () {
        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);
        return JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: this.code_challenge_method,
          code_challenge: this.code_challenge,
        }, Buffer.from('not THE secret'), 'HS256', { issuer: 'client', audience: this.provider.issuer, expiresIn: 30 }).then((request) => this.wrap({
          agent: this.agent,
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
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][1]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][1]).to.have.property('error_description').that.matches(/could not validate Request Object/);
          }));
      });

      it('rejects "registration" parameter part of the Request Object', function () {
        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);

        return JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: this.code_challenge_method,
          code_challenge: this.code_challenge,
          registration: 'foo',
        }, Buffer.from('secret'), 'HS256', { issuer: 'client', audience: this.provider.issuer, expiresIn: 30 }).then((request) => this.wrap({
          agent: this.agent,
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
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][1]).to.have.property('message', 'registration_not_supported');
          }));
      });

      it('handles unrecognized parameters', async function () {
        const client = await this.provider.Client.find('client-with-HS-sig');
        let [key] = client.symmetricKeyStore.selectForSign({ alg: 'HS256' });
        key = await importJWK(key);
        return JWT.sign({
          jti: crypto.randomBytes(16).toString('base64url'),
          client_id: 'client-with-HS-sig',
          unrecognized: true,
          response_type: 'code',
          scope: 'openid',
          redirect_uri: 'https://client.example.com/cb',
          code_challenge_method: this.code_challenge_method,
          code_challenge: this.code_challenge,
        }, key, 'HS256', { issuer: 'client-with-HS-sig', audience: this.provider.issuer, expiresIn: 30 }).then((request) => this.wrap({
          agent: this.agent,
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
