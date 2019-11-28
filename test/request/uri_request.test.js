const { parse } = require('url');

const jose = require('jose');
const sinon = require('sinon').createSandbox();
const nock = require('nock');
const { expect } = require('chai');

const JWT = require('../../lib/helpers/jwt');
const RequestUriCache = require('../../lib/helpers/request_uri_cache');
const bootstrap = require('../test_helper');

describe('request Uri features', () => {
  before(bootstrap(__dirname));
  beforeEach(nock.cleanAll);

  describe('configuration features.requestUri', () => {
    it('extends discovery', function () {
      return this.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('request_uri_parameter_supported', true);
          expect(response.body).not.to.have.property('require_request_uri_registration');
        });
    });

    context('requireUriRegistration', () => {
      before(function () {
        this.provider.enable('requestObjects', { requestUri: true, requireUriRegistration: true });
      });

      after(function () {
        this.provider.enable('requestObjects', { requestUri: true, requireUriRegistration: false });
      });

      it('extends discovery', function () {
        return this.agent.get('/.well-known/openid-configuration')
          .expect(200)
          .expect((response) => {
            expect(response.body).to.have.property('request_uri_parameter_supported', true);
            expect(response.body).to.have.property('require_request_uri_registration', true);
          });
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
    ['/auth', 'get', 'authorization.error', 302, 302, redirectSuccess],
    ['/auth', 'post', 'authorization.error', 302, 302, redirectSuccess],
    ['/device/auth', 'post', 'device_authorization.error', 200, 400, httpSuccess],
  ].forEach(([route, verb, error, successCode, errorCode, successFnCheck]) => {
    describe(`${route} ${verb} passing request parameters in request_uri`, () => {
      before(function () { return this.login(); });
      after(function () { return this.logout(); });

      it('works with signed by an actual alg (https)', async function () {
        const key = (await this.provider.Client.find('client-with-HS-sig')).keystore.get({ alg: 'HS256' });
        const request = await JWT.sign({
          client_id: 'client-with-HS-sig',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, key, 'HS256', { issuer: 'client-with-HS-sig', audience: this.provider.issuer });

        nock('https://client.example.com')
          .get('/request')
          .reply(200, request);

        return this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request_uri: `https://client.example.com/request#${Math.random()}`,
            scope: 'openid',
            client_id: 'client-with-HS-sig',
            response_type: 'code',
          },
        })
          .expect(successCode)
          .expect(successFnCheck);
      });

      it('works with signed by an actual alg (http)', async function () {
        const key = (await this.provider.Client.find('client-with-HS-sig')).keystore.get({ alg: 'HS256' });
        const request = await JWT.sign({
          client_id: 'client-with-HS-sig',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, key, 'HS256', { issuer: 'client-with-HS-sig', audience: this.provider.issuer });

        nock('http://client.example.com')
          .get('/request')
          .reply(200, request);

        return this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request_uri: `http://client.example.com/request#${Math.random()}`,
            scope: 'openid',
            client_id: 'client-with-HS-sig',
            response_type: 'code',
          },
        })
          .expect(successCode)
          .expect(successFnCheck);
      });

      it('works with signed by none (https)', async function () {
        const request = await JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, null, 'none', { issuer: 'client', audience: this.provider.issuer });

        nock('https://client.example.com')
          .get('/request')
          .reply(200, request);

        return this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request_uri: `https://client.example.com/request#${Math.random()}`,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(successCode)
          .expect(successFnCheck);
      });

      it('forbids http signed by none', async function () {
        const spy = sinon.spy();
        this.provider.once(error, spy);

        const request = await JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, null, 'none', { issuer: 'client', audience: this.provider.issuer });

        nock('http://client.example.com')
          .get('/request')
          .reply(200, request);

        return this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request_uri: `http://client.example.com/request#${Math.random()}`,
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
              'Request Object from insecure request_uri must be signed and/or symmetrically encrypted',
            );
          });
      });

      it('forbids non urn: or web schemes', function () {
        const spy = sinon.spy();
        this.provider.once(error, spy);

        return this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request_uri: 'some-scheme://client.example.com/request',
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][1]).to.have.property('message', 'invalid_request_uri');
            expect(spy.args[0][1]).to.have.property(
              'error_description',
              'invalid request_uri scheme',
            );
          });
      });

      describe('urn support', () => {
        afterEach(sinon.restore);

        it('urn cannot be registered and will fail on client#requestUriAllowed()', function () {
          const spy = sinon.spy();
          this.provider.once(error, spy);
          sinon.spy(this.provider.Client.prototype, 'requestUriAllowed');

          return this.wrap({
            agent: this.agent,
            route,
            verb,
            auth: {
              request_uri: 'urn:example',
              scope: 'openid',
              client_id: 'client',
              response_type: 'code',
            },
          })
            .expect(errorCode)
            .expect(() => {
              expect(this.provider.Client.prototype.requestUriAllowed.calledOnce).to.be.true;
              expect(spy.calledOnce).to.be.true;
              expect(spy.args[0][1]).to.have.property('message', 'invalid_request_uri');
              expect(spy.args[0][1]).to.have.property(
                'error_description',
                'provided request_uri is not whitelisted',
              );
            });
        });

        it('but this is overloadable public API', function () {
          const spy = sinon.spy();
          this.provider.once(error, spy);
          sinon.stub(this.provider.Client.prototype, 'requestUriAllowed').returns(true);

          return this.wrap({
            agent: this.agent,
            route,
            verb,
            auth: {
              request_uri: 'urn:example',
              scope: 'openid',
              client_id: 'client',
              response_type: 'code',
            },
          })
            .expect(errorCode)
            .expect(() => {
              expect(this.provider.Client.prototype.requestUriAllowed.calledOnce).to.be.true;
              expect(spy.calledOnce).to.be.true;
              expect(spy.args[0][1]).to.have.property('message', 'invalid_request_uri');
              expect(spy.args[0][1]).to.have.property(
                'error_description',
                'could not load or parse request_uri (resolving request_uri by URN is not implemented)',
              );
            });
        });

        it('so is the request uri cache', async function () {
          const spy = sinon.spy();
          this.provider.once(error, spy);
          sinon.stub(this.provider.Client.prototype, 'requestUriAllowed').returns(true);

          const request = await JWT.sign({
            client_id: 'client',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
          }, null, 'none', { issuer: 'client', audience: this.provider.issuer });

          sinon.stub(this.provider.requestUriCache, 'resolveUrn').returns(request);

          return this.wrap({
            agent: this.agent,
            route,
            verb,
            auth: {
              request_uri: 'urn:example',
              scope: 'openid',
              client_id: 'client',
              response_type: 'code',
            },
          })
            .expect(successCode)
            .expect(successFnCheck)
            .expect(() => {
              expect(this.provider.requestUriCache.resolveUrn.calledOnce).to.be.true;
            });
        });
      });

      context('when client has requestUris set', () => {
        before(async function () {
          (await this.provider.Client.find('client')).requestUris = ['https://thisoneisallowed.com'];
        });

        after(async function () {
          (await this.provider.Client.find('client')).requestUris = undefined;
        });

        it('checks the whitelist', async function () {
          const request = await JWT.sign({
            client_id: 'client',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
          }, null, 'none', { issuer: 'client', audience: this.provider.issuer });

          nock('https://thisoneisallowed.com')
            .get('/')
            .reply(200, request);

          return this.wrap({
            agent: this.agent,
            route,
            verb,
            auth: {
              request_uri: 'https://thisoneisallowed.com',
              scope: 'openid',
              client_id: 'client',
              response_type: 'code',
            },
          })
            .expect(successCode)
            .expect(successFnCheck);
        });

        it('allows for fragments to be provided', async function () {
          const request = await JWT.sign({
            client_id: 'client',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
          }, null, 'none', { issuer: 'client', audience: this.provider.issuer });

          nock('https://thisoneisallowed.com#hash234')
            .get('/')
            .reply(200, request);

          return this.wrap({
            agent: this.agent,
            route,
            verb,
            auth: {
              request_uri: 'https://thisoneisallowed.com#hash234',
              scope: 'openid',
              client_id: 'client',
              response_type: 'code',
            },
          })
            .expect(successCode)
            .expect(successFnCheck);
        });

        it('doesnt allow to bypass these', function () {
          const spy = sinon.spy();
          this.provider.once(error, spy);

          return this.wrap({
            agent: this.agent,
            route,
            verb,
            auth: {
              request_uri: 'https://thisoneisnot.com',
              scope: 'openid',
              client_id: 'client',
              response_type: 'code',
            },
          })
            .expect(errorCode)
            .expect(() => {
              expect(spy.calledOnce).to.be.true;
              expect(spy.args[0][1]).to.have.property('message', 'invalid_request_uri');
              expect(spy.args[0][1]).to.have.property(
                'error_description',
                'provided request_uri is not whitelisted',
              );
            });
        });
      });

      it('handles got lib errors', function () {
        const spy = sinon.spy();
        this.provider.once(error, spy);

        nock('https://client.example.com')
          .get('/request')
          .reply(500);

        return this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request_uri: `https://client.example.com/request#${Math.random()}`,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][1]).to.have.property('message', 'invalid_request_uri');
            expect(spy.args[0][1]).to.have.property('error_description', 'could not load or parse request_uri (unexpected request_uri response status code, expected 200 OK, got 500 Internal Server Error)');
          });
      });

      it('doesnt accepts 200s, rejects even on redirect', function () {
        const spy = sinon.spy();
        this.provider.once(error, spy);

        nock('https://client.example.com')
          .get('/request')
          .reply(302, 'redirecting', {
            location: '/someotherrequest',
          });

        return this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request_uri: `https://client.example.com/request#${Math.random()}`,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][1]).to.have.property('message', 'invalid_request_uri');
            expect(spy.args[0][1]).to.have.property('error_description').and.matches(/expected 200 OK, got 302 Found/);
          });
      });

      it('request and request_uri cannot be used together', async function () {
        const spy = sinon.spy();
        this.provider.once(error, spy);

        const request = await JWT.sign({
          client_id: 'client',
          response_type: 'code',
          request: 'request inception',
          redirect_uri: 'https://client.example.com/cb',
        }, null, 'none', { issuer: 'client', audience: this.provider.issuer });

        return this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request,
            request_uri: `https://client.example.com/request#${Math.random()}`,
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
              'request and request_uri parameters MUST NOT be used together',
            );
          });
      });

      it('doesnt allow request inception', async function () {
        const spy = sinon.spy();
        this.provider.once(error, spy);

        const request = await JWT.sign({
          client_id: 'client',
          response_type: 'code',
          request: 'request inception',
          redirect_uri: 'https://client.example.com/cb',
        }, null, 'none', { issuer: 'client', audience: this.provider.issuer });

        nock('https://client.example.com')
          .get('/request')
          .reply(200, request);

        return this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request_uri: `https://client.example.com/request#${Math.random()}`,
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
          });
      });

      it('doesnt allow requestUri inception', async function () {
        const spy = sinon.spy();
        this.provider.once(error, spy);

        const request = await JWT.sign({
          client_id: 'client',
          response_type: 'code',
          request_uri: 'request uri inception',
          redirect_uri: 'https://client.example.com/cb',
        }, null, 'none', { issuer: 'client', audience: this.provider.issuer });

        nock('https://client.example.com')
          .get('/request')
          .reply(200, request);

        return this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request_uri: `https://client.example.com/request#${Math.random()}`,
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
          });
      });

      it('doesnt allow client_id to differ', async function () {
        const spy = sinon.spy();
        this.provider.once(error, spy);

        const request = await JWT.sign({
          client_id: 'client2',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, null, 'none', { issuer: 'client2', audience: this.provider.issuer });

        nock('https://client.example.com')
          .get('/request')
          .reply(200, request);

        return this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request_uri: `https://client.example.com/request#${Math.random()}`,
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
          });
      });

      it('handles invalid signed looklike jwts', function () {
        const spy = sinon.spy();
        this.provider.once(error, spy);

        nock('https://client.example.com')
          .get('/request')
          .reply(200, 'definitely.notsigned.jwt');

        return this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request_uri: `https://client.example.com/request#${Math.random()}`,
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

      it('doesnt allow clients with predefined alg to bypass this alg', async function () {
        const spy = sinon.spy();
        this.provider.once(error, spy);

        const request = await JWT.sign({
          client_id: 'client-with-HS-sig',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, null, 'none', { issuer: 'client-with-HS-sig', audience: this.provider.issuer });

        nock('https://client.example.com')
          .get('/request')
          .reply(200, request);

        return this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request_uri: `https://client.example.com/request#${Math.random()}`,
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
          });
      });

      it('unsupported algs must not be used', async function () {
        const spy = sinon.spy();
        this.provider.once(error, spy);
        const secret = (await this.provider.Client.find('client')).clientSecret;
        const key = jose.JWK.asKey(secret);

        const request = await JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, key, 'HS384', { issuer: 'client', audience: this.provider.issuer });

        nock('https://client.example.com')
          .get('/request')
          .reply(200, request);

        return this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request_uri: `https://client.example.com/request#${Math.random()}`,
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
          });
      });

      it('bad signatures will be rejected', async function () {
        const spy = sinon.spy();
        this.provider.once(error, spy);

        const key = (await this.provider.Client.find('client-with-HS-sig')).keystore.get({ alg: 'HS256' });
        const request = await JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, key, 'HS256', { issuer: 'client', audience: this.provider.issuer });

        nock('https://client.example.com')
          .get('/request')
          .reply(200, request);

        return this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request_uri: `https://client.example.com/request#${Math.random()}`,
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
          });
      });
    });
  });

  context('caching of the request_uris', () => {
    it('caches the uris', async function () {
      const cache = new RequestUriCache(this.provider);
      nock('https://client.example.com')
        .get('/cachedRequest')
        .reply(200, 'content')
        .get('/cachedRequest')
        .reply(200, 'content2');

      const first = await cache.resolveWebUri('https://client.example.com/cachedRequest#1');
      const second = await cache.resolveWebUri('https://client.example.com/cachedRequest#1');
      const third = await cache.resolveWebUri('https://client.example.com/cachedRequest#2');
      const fourth = await cache.resolveWebUri('https://client.example.com/cachedRequest#2');

      expect(first).to.equal(second);
      expect(first).not.to.equal(third);
      expect(third).to.equal(fourth);
    });

    it('respects provided response max-age header', async function () {
      this.retries(1);

      const cache = new RequestUriCache(this.provider);
      nock('https://client.example.com')
        .get('/cachedRequest')
        .reply(200, 'content24', {
          'Cache-Control': 'private, max-age=5',
        });

      await cache.resolveWebUri('https://client.example.com/cachedRequest');
      const dump = cache.cache.dump();
      expect(dump).to.have.lengthOf(1);
      expect((dump[0].e - Date.now()) / 1000 | 0).to.be.closeTo(5, 1); // eslint-disable-line no-bitwise, max-len
    });

    it('respects provided response expires header', async function () {
      this.retries(1);

      const cache = new RequestUriCache(this.provider);
      nock('https://client.example.com')
        .get('/cachedRequest')
        .reply(200, 'content24', {
          Expires: new Date(Date.now() + (5 * 1000)).toGMTString(),
        });

      await cache.resolveWebUri('https://client.example.com/cachedRequest');
      const dump = cache.cache.dump();
      expect(dump).to.have.lengthOf(1);
      expect((dump[0].e - Date.now()) / 1000 | 0).to.be.closeTo(5, 1); // eslint-disable-line no-bitwise, max-len
    });
  });
});
