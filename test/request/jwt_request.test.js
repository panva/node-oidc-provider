const bootstrap = require('../test_helper');
const JWT = require('../../lib/helpers/jwt');
const sinon = require('sinon');
const {
  expect,
} = require('chai');
const {
  parse,
} = require('url');

const route = '/auth';

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

  ['get', 'post'].forEach((verb) => {
    describe(`${route} ${verb} passing request parameters as JWTs`, () => {
      before(function () {
        return this.login();
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
          .expect(302)
          .expect((response) => {
            const expected = parse('https://client.example.com/cb', true);
            const actual = parse(response.headers.location, true);
            ['protocol', 'host', 'pathname'].forEach((attr) => {
              expect(actual[attr]).to.equal(expected[attr]);
            });
            expect(actual.query).to.have.property('code');
          }));
      });

      it('can contain claims parameter as JSON', function () {
        return JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
          claims: JSON.stringify({ id_token: { email: null } }),
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
          .expect(302)
          .expect((response) => {
            const expected = parse('https://client.example.com/cb', true);
            const actual = parse(response.headers.location, true);
            ['protocol', 'host', 'pathname'].forEach((attr) => {
              expect(actual[attr]).to.equal(expected[attr]);
            });
            expect(actual.query).to.have.property('code');
          }));
      });

      it('can contain claims parameter as object', function () {
        return JWT.sign({
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
          .expect(302)
          .expect((response) => {
            const expected = parse('https://client.example.com/cb', true);
            const actual = parse(response.headers.location, true);
            ['protocol', 'host', 'pathname'].forEach((attr) => {
              expect(actual[attr]).to.equal(expected[attr]);
            });
            expect(actual.query).to.have.property('code');
          }));
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
          .expect(302)
          .expect((response) => {
            const expected = parse('https://client.example.com/cb', true);
            const actual = parse(response.headers.location, true);
            ['protocol', 'host', 'pathname'].forEach((attr) => {
              expect(actual[attr]).to.equal(expected[attr]);
            });
            expect(actual.query).to.have.property('code');
          }));
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
          .expect(302)
          .expect((response) => {
            const expected = parse('https://client.example.com/cb', true);
            const actual = parse(response.headers.location, true);
            ['protocol', 'host', 'pathname'].forEach((attr) => {
              expect(actual[attr]).to.equal(expected[attr]);
            });
            expect(actual.query).to.have.property('code');
          }));
      });

      it('doesnt allow request inception', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);

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
          .expect(302)
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
        this.provider.once('authorization.error', spy);

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
          .expect(302)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][0]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][0]).to.have.property(
              'error_description',
              'request object must not contain request or request_uri properties',
            );
          }));
      });

      it('doesnt allow response_type to differ', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);

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
          .expect(302)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][0]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][0]).to.have.property(
              'error_description',
              'request response_type must equal the one in request parameters',
            );
          }));
      });

      it('doesnt allow client_id to differ', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);

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
          .expect(302)
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
        this.provider.once('authorization.error', spy);

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
          .expect(302)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][0]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][0]).to.have.property('error_description').and.matches(/could not parse request object as valid JWT/);
          });
      });

      it('doesnt allow clients with predefined alg to bypass this alg', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);

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
          .expect(302)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][0]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][0]).to.have.property(
              'error_description',
              'the preregistered alg must be used in request or request_uri',
            );
          }));
      });


      it('bad signatures will be rejected', async function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);

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
          .expect(302)
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
          .expect(302)
          .expect((response) => {
            const expected = parse('https://client.example.com/cb', true);
            const actual = parse(response.headers.location, true);
            ['protocol', 'host', 'pathname'].forEach((attr) => {
              expect(actual[attr]).to.equal(expected[attr]);
            });
            expect(actual.query).to.have.property('code');
          }));
      });
    });
  });
});
