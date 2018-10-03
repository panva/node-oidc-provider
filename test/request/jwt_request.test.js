const { parse } = require('url');

const sinon = require('sinon');
const { expect } = require('chai');

const JWT = require('../../lib/helpers/jwt');
const bootstrap = require('../test_helper');

describe('request parameter features', () => {
  before(bootstrap(__dirname));

  describe('configuration features.requestUri', () => {
    it('extends discovery', function () {
      return this.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('request_parameter_supported', true);
        });
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
    ['/auth', 'get', 'authorization.error', 302, 302, redirectSuccess, 'authorization.success'],
    ['/auth', 'post', 'authorization.error', 302, 302, redirectSuccess, 'authorization.success'],
    ['/device/auth', 'post', 'device_authorization.error', 200, 400, httpSuccess, 'device_authorization.success'],
  ].forEach(([route, verb, errorEvt, successCode, errorCode, successFnCheck, successEvt]) => {
    describe(`${route} ${verb} passing request parameters as JWTs`, () => {
      before(function () {
        return this.login({
          claims: { id_token: { email: null } },
        });
      });
      after(function () {
        i(this.provider).configuration().clockTolerance = 0;
        return this.logout();
      });

      it('works with signed by none', function () {
        return JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then(request => this.wrap({
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
      });

      it('can contain max_age parameter as a number and it (and other params too) will be forced as string', async function () {
        const spy = sinon.spy();
        this.provider.once(successEvt, spy);

        await JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          max_age: 300,
        }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then(request => this.wrap({
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

      it('can contain claims parameter as JSON', async function () {
        const spy = sinon.spy();
        this.provider.once(successEvt, spy);
        const claims = JSON.stringify({ id_token: { email: null } });

        await JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          claims,
        }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then(request => this.wrap({
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
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          claims: { id_token: { email: null } },
        }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then(request => this.wrap({
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

      it('can accept request objects issued within acceptable system clock skew', async function () {
        const key = (await this.provider.Client.find('client-with-HS-sig')).keystore.get({
          alg: 'HS256',
        });
        i(this.provider).configuration().clockTolerance = 10;
        return JWT.sign({
          iat: Math.ceil(Date.now() / 1000) + 5,
          client_id: 'client-with-HS-sig',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, key, 'HS256', { issuer: 'client-with-HS-sig', audience: this.provider.issuer }).then(request => this.wrap({
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

      it('works with signed by an actual HS', async function () {
        const key = (await this.provider.Client.find('client-with-HS-sig')).keystore.get({
          alg: 'HS256',
        });
        return JWT.sign({
          client_id: 'client-with-HS-sig',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, key, 'HS256', { issuer: 'client-with-HS-sig', audience: this.provider.issuer }).then(request => this.wrap({
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

      it('doesnt allow request inception', function () {
        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);

        return JWT.sign({
          client_id: 'client',
          response_type: 'code',
          request: 'request inception',
          redirect_uri: 'https://client.example.com/cb',
        }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then(request => this.wrap({
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
            expect(spy.args[0][0]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][0]).to.have.property(
              'error_description',
              'request object must not contain request or request_uri properties',
            );
          }));
      });

      it('doesnt allow requestUri inception', function () {
        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);

        return JWT.sign({
          client_id: 'client',
          response_type: 'code',
          request_uri: 'request uri inception',
          redirect_uri: 'https://client.example.com/cb',
        }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then(request => this.wrap({
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
            expect(spy.args[0][0]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][0]).to.have.property(
              'error_description',
              'request object must not contain request or request_uri properties',
            );
          }));
      });

      if (route !== '/device/auth') {
        it('can contain resource parameter as an Array', async function () {
          const spy = sinon.spy();
          this.provider.once(successEvt, spy);

          await JWT.sign({
            client_id: 'client',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
            resource: ['https://rp.example.com/api'],
          }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then(request => this.wrap({
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
            spy.calledWithMatch({ oidc: { params: { resource: ['https://rp.example.com/api'] } } }),
          ).to.be.true;
        });

        it('doesnt allow response_type to differ', function () {
          const spy = sinon.spy();
          this.provider.once(errorEvt, spy);

          return JWT.sign({
            client_id: 'client',
            response_type: 'id_token',
            redirect_uri: 'https://client.example.com/cb',
          }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then(request => this.wrap({
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
              expect(spy.args[0][0]).to.have.property('message', 'invalid_request_object');
              expect(spy.args[0][0]).to.have.property(
                'error_description',
                'request response_type must equal the one in request parameters',
              );
            }));
        });
      }

      it('doesnt allow client_id to differ', function () {
        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);

        return JWT.sign({
          client_id: 'client2',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, null, 'none', { issuer: 'client2', audience: this.provider.issuer }).then(request => this.wrap({
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
            expect(spy.args[0][0]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][0]).to.have.property(
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
            expect(spy.args[0][0]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][0]).to.have.property('error_description').and.matches(/could not parse request object as valid JWT/);
          });
      });

      it('doesnt allow clients with predefined alg to bypass this alg', function () {
        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);

        return JWT.sign({
          client_id: 'client-with-HS-sig',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, null, 'none', { issuer: 'client-with-HS-sig', audience: this.provider.issuer }).then(request => this.wrap({
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
            expect(spy.args[0][0]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][0]).to.have.property(
              'error_description',
              'the preregistered alg must be used in request or request_uri',
            );
          }));
      });

      it('unsupported algs must not be used', async function () {
        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);
        const key = (await this.provider.Client.find('client')).keystore.get({
          alg: 'HS384',
        });
        return JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, key, 'HS384', { issuer: 'client', audience: this.provider.issuer }).then(request => this.wrap({
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
            expect(spy.args[0][0]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][0]).to.have.property('error_description', 'unsupported signed request alg');
          }));
      });

      it('bad signatures will be rejected', async function () {
        const spy = sinon.spy();
        this.provider.once(errorEvt, spy);

        const key = (await this.provider.Client.find('client-with-HS-sig')).keystore.get({
          alg: 'HS256',
        });
        return JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, key, 'HS256', { issuer: 'client', audience: this.provider.issuer }).then(request => this.wrap({
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
            expect(spy.args[0][0]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][0]).to.have.property('error_description').that.matches(/could not validate request object/);
          }));
      });

      it('handles unrecognized parameters', async function () {
        const key = (await this.provider.Client.find('client-with-HS-sig')).keystore.get({
          alg: 'HS256',
        });
        return JWT.sign({
          client_id: 'client-with-HS-sig',
          unrecognized: true,
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, key, 'HS256', { issuer: 'client-with-HS-sig', audience: this.provider.issuer }).then(request => this.wrap({
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
