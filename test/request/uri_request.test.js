const { parse } = require('url');

const sinon = require('sinon');
const nock = require('nock');
const { expect } = require('chai');

const JWT = require('../../lib/helpers/jwt');
const RequestUriCache = require('../../lib/helpers/request_uri_cache');
const bootstrap = require('../test_helper');

describe('request Uri features', () => {
  before(bootstrap(__dirname));

  describe('configuration features.requestUri', () => {
    it('extends discovery', function () {
      return this.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('request_uri_parameter_supported', true);
          expect(response.body).not.to.have.property('require_request_uri_registration');
        });
    });

    context('requireRequestUriRegistration', () => {
      before(function () {
        i(this.provider).configuration().features.requestUri = {
          requireRequestUriRegistration: true,
        };
      });

      after(function () {
        i(this.provider).configuration().features.requestUri = true;
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

      it('works with signed by an actual alg', async function () {
        const key = (await this.provider.Client.find('client-with-HS-sig')).keystore.get({ alg: 'HS256' });
        return JWT.sign({
          client_id: 'client-with-HS-sig',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, key, 'HS256', { issuer: 'client-with-HS-sig', audience: this.provider.issuer }).then((request) => {
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
      });

      it('works with signed by none', function () {
        return JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then((request) => {
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
      });

      context('caching of the request_uris', () => {
        it('caches the uris', async function () {
          const cache = new RequestUriCache(this.provider);
          nock('https://client.example.com')
            .get('/cachedRequest')
            .reply(200, 'content')
            .get('/cachedRequest')
            .reply(200, 'content2');

          const first = await cache.resolve('https://client.example.com/cachedRequest#1');
          const second = await cache.resolve('https://client.example.com/cachedRequest#1');
          const third = await cache.resolve('https://client.example.com/cachedRequest#2');
          const fourth = await cache.resolve('https://client.example.com/cachedRequest#2');

          expect(first).to.equal(second);
          expect(first).not.to.equal(third);
          expect(third).to.equal(fourth);
        });

        it('respects provided response max-age header', async function () {
          const cache = new RequestUriCache(this.provider);
          nock('https://client.example.com')
            .get('/cachedRequest')
            .reply(200, 'content24', {
              'Cache-Control': 'private, max-age=5',
            });

          await cache.resolve('https://client.example.com/cachedRequest');
          const dump = cache.cache.dump();
          expect(dump).to.have.lengthOf(1);
          expect((dump[0].e - Date.now()) / 1000 | 0).to.be.within(4, 5); // eslint-disable-line no-bitwise, max-len
        });

        it('respects provided response expires header', async function () {
          const cache = new RequestUriCache(this.provider);
          nock('https://client.example.com')
            .get('/cachedRequest')
            .reply(200, 'content24', {
              Expires: new Date(Date.now() + (5 * 1000)).toGMTString(),
            });

          await cache.resolve('https://client.example.com/cachedRequest');
          const dump = cache.cache.dump();
          expect(dump).to.have.lengthOf(1);
          expect((dump[0].e - Date.now()) / 1000 | 0).to.be.within(4, 5); // eslint-disable-line no-bitwise, max-len
        });
      });

      it('doesnt allow too long request_uris', function () {
        const spy = sinon.spy();
        this.provider.once(error, spy);

        return this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request_uri: 'https://veeeeryloong.com/uri#Lorem&Ipsum&is&simply&dummy&text&of&the&printing&and&typesetting&industry.&Lorem&Ipsum&has&been&the&industrys&standard&dummy&text&ever&since&the&1500s,&when&an&unknown&printer&took&a&galley&of&type&and&scrambled&it&to&make&a&type&specimen&book.&It&has&survived&not&only&five&centuries,&but&also&the&leap&into&electronic&typesetting,&remaining&essentially&unchanged.&It&was&popularised&in&the&1960s&with&the&release&of&Letraset&sheets&containing&Lorem&Ipsum&passages,&and&more&recently&with&desktop&publishing&software&like&Aldus&PageMaker&including&versions&of&Lorem&Ipsum',
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][0]).to.have.property('message', 'invalid_request_uri');
            expect(spy.args[0][0]).to.have.property(
              'error_description',
              'the request_uri MUST NOT exceed 512 characters',
            );
          });
      });

      it('requires https protocol to be used', function () {
        const spy = sinon.spy();
        this.provider.once(error, spy);

        return this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request_uri: 'http://rp.example.com/request_uri#123',
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][0]).to.have.property('message', 'invalid_request_uri');
            expect(spy.args[0][0]).to.have.property(
              'error_description',
              'request_uri must use https scheme',
            );
          });
      });

      context('when client has requestUris set', () => {
        before(async function () {
          (await this.provider.Client.find('client')).requestUris = ['https://thisoneisallowed.com'];
        });

        after(async function () {
          (await this.provider.Client.find('client')).requestUris = undefined;
        });

        it('checks the whitelist', function () {
          return JWT.sign({
            client_id: 'client',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
          }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then((request) => {
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
        });

        it('allows for fragments to be provided', function () {
          return JWT.sign({
            client_id: 'client',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb',
          }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then((request) => {
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
              expect(spy.args[0][0]).to.have.property('message', 'invalid_request_uri');
              expect(spy.args[0][0]).to.have.property(
                'error_description',
                'not registered request_uri provided',
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
            expect(spy.args[0][0]).to.have.property('message', 'invalid_request_uri');
            expect(spy.args[0][0]).to.have.property('error_description', 'could not load or parse request_uri (Response code 500 (Internal Server Error))');
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
            expect(spy.args[0][0]).to.have.property('message', 'invalid_request_uri');
            expect(spy.args[0][0]).to.have.property('error_description').and.matches(/expected 200, got 302/);
          });
      });

      it('request and request_uri cannot be used together', function () {
        const spy = sinon.spy();
        this.provider.once(error, spy);

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
            request_uri: `https://client.example.com/request#${Math.random()}`,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code',
          },
        })
          .expect(errorCode)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
            expect(spy.args[0][0]).to.have.property('message', 'invalid_request');
            expect(spy.args[0][0]).to.have.property(
              'error_description',
              'request and request_uri parameters MUST NOT be used together',
            );
          }));
      });

      it('doesnt allow request inception', function () {
        const spy = sinon.spy();
        this.provider.once(error, spy);

        return JWT.sign({
          client_id: 'client',
          response_type: 'code',
          request: 'request inception',
          redirect_uri: 'https://client.example.com/cb',
        }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then((request) => {
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
              expect(spy.args[0][0]).to.have.property('message', 'invalid_request_object');
              expect(spy.args[0][0]).to.have.property(
                'error_description',
                'request object must not contain request or request_uri properties',
              );
            });
        });
      });

      it('doesnt allow requestUri inception', function () {
        const spy = sinon.spy();
        this.provider.once(error, spy);

        return JWT.sign({
          client_id: 'client',
          response_type: 'code',
          request_uri: 'request uri inception',
          redirect_uri: 'https://client.example.com/cb',
        }, null, 'none', { issuer: 'client', audience: this.provider.issuer }).then((request) => {
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
              expect(spy.args[0][0]).to.have.property('message', 'invalid_request_object');
              expect(spy.args[0][0]).to.have.property(
                'error_description',
                'request object must not contain request or request_uri properties',
              );
            });
        });
      });

      it('doesnt allow client_id to differ', function () {
        const spy = sinon.spy();
        this.provider.once(error, spy);

        return JWT.sign({
          client_id: 'client2',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, null, 'none', { issuer: 'client2', audience: this.provider.issuer }).then((request) => {
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
              expect(spy.args[0][0]).to.have.property('message', 'invalid_request_object');
              expect(spy.args[0][0]).to.have.property(
                'error_description',
                'request client_id must equal the one in request parameters',
              );
            });
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
            expect(spy.args[0][0]).to.have.property('message', 'invalid_request_object');
            expect(spy.args[0][0]).to.have.property('error_description').and.matches(/could not parse request object as valid JWT/);
          });
      });

      it('doesnt allow clients with predefined alg to bypass this alg', function () {
        const spy = sinon.spy();
        this.provider.once(error, spy);

        return JWT.sign({
          client_id: 'client-with-HS-sig',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, null, 'none', { issuer: 'client-with-HS-sig', audience: this.provider.issuer }).then((request) => {
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
              expect(spy.args[0][0]).to.have.property('message', 'invalid_request_object');
              expect(spy.args[0][0]).to.have.property(
                'error_description',
                'the preregistered alg must be used in request or request_uri',
              );
            });
        });
      });

      it('unsupported algs must not be used', async function () {
        const spy = sinon.spy();
        this.provider.once(error, spy);
        const key = (await this.provider.Client.find('client')).keystore.get({
          alg: 'HS384',
        });
        return JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, key, 'HS384', { issuer: 'client', audience: this.provider.issuer }).then((request) => {
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
              expect(spy.args[0][0]).to.have.property('message', 'invalid_request_object');
              expect(spy.args[0][0]).to.have.property('error_description', 'unsupported signed request alg');
            });
        });
      });

      it('bad signatures will be rejected', async function () {
        const spy = sinon.spy();
        this.provider.once(error, spy);

        const key = (await this.provider.Client.find('client-with-HS-sig')).keystore.get({ alg: 'HS256' });
        return JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb',
        }, key, 'HS256', { issuer: 'client', audience: this.provider.issuer }).then((request) => {
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
              expect(spy.args[0][0]).to.have.property('message', 'invalid_request_object');
              expect(spy.args[0][0]).to.have.property('error_description').that.matches(/could not validate request object/);
            });
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

      const first = await cache.resolve('https://client.example.com/cachedRequest#1');
      const second = await cache.resolve('https://client.example.com/cachedRequest#1');
      const third = await cache.resolve('https://client.example.com/cachedRequest#2');
      const fourth = await cache.resolve('https://client.example.com/cachedRequest#2');

      expect(first).to.equal(second);
      expect(first).not.to.equal(third);
      expect(third).to.equal(fourth);
    });

    it('respects provided response max-age header', async function () {
      const cache = new RequestUriCache(this.provider);
      nock('https://client.example.com')
        .get('/cachedRequest')
        .reply(200, 'content24', {
          'Cache-Control': 'private, max-age=5',
        });

      await cache.resolve('https://client.example.com/cachedRequest');
      const dump = cache.cache.dump();
      expect(dump).to.have.lengthOf(1);
      expect((dump[0].e - Date.now()) / 1000 | 0).to.be.within(4, 5); // eslint-disable-line no-bitwise, max-len
    });

    it('respects provided response expires header', async function () {
      const cache = new RequestUriCache(this.provider);
      nock('https://client.example.com')
        .get('/cachedRequest')
        .reply(200, 'content24', {
          Expires: new Date(Date.now() + (5 * 1000)).toGMTString(),
        });

      await cache.resolve('https://client.example.com/cachedRequest');
      const dump = cache.cache.dump();
      expect(dump).to.have.lengthOf(1);
      expect((dump[0].e - Date.now()) / 1000 | 0).to.be.within(4, 5); // eslint-disable-line no-bitwise, max-len
    });
  });
});
