'use strict';

const bootstrap = require('../test_helper');
const RequestUriCache = require('../../lib/helpers/request_uri_cache');
const JWT = require('../../lib/helpers/jwt');
const sinon = require('sinon');
const nock = require('nock');
const { expect } = require('chai');
const { parse } = require('url');

const route = '/auth';

describe('request Uri features', function () {
  before(bootstrap(__dirname)); // provider, agent, wrap

  describe('configuration features.requestUri', function () {
    it('extends discovery', function () {
      return this.agent.get('/.well-known/openid-configuration')
      .expect(200)
      .expect((response) => {
        expect(response.body).to.have.property('request_uri_parameter_supported', true);
        expect(response.body).not.to.have.property('require_request_uri_registration');
      });
    });

    context('requireRequestUriRegistration', function () {
      before(function () {
        i(this.provider).configuration().features.requestUri = { requireRequestUriRegistration: true };
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

  ['get', 'post'].forEach((verb) => {
    describe(`${route} ${verb} passing request parameters in request_uri`, function () {
      before(function () { return this.login(); });
      after(function () { return this.logout(); });

      it('works with signed by an actual alg', function* () {
        const key = (yield this.provider.Client.find('client-with-HS-sig')).keystore.get({ alg: 'HS256' });
        return JWT.sign({
          client_id: 'client-with-HS-sig',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb'
        }, key, 'HS256').then((request) => {
          nock('https://client.example.com')
          .get('/request')
          .reply(200, request);

          return this.wrap({
            agent: this.agent,
            route,
            verb,
            auth: {
              request_uri: `https://client.example.com/request#${Date.now()}`,
              scope: 'openid',
              client_id: 'client-with-HS-sig',
              response_type: 'code'
            }
          })
        .expect(302)
        .expect((response) => {
          const expected = parse('https://client.example.com/cb', true);
          const actual = parse(response.headers.location, true);
          ['protocol', 'host', 'pathname'].forEach((attr) => {
            expect(actual[attr]).to.equal(expected[attr]);
          });
          expect(actual.query).to.have.property('code');
        });
        });
      });

      it('works with signed by none', function () {
        return JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb'
        }, null, 'none').then((request) => {
          nock('https://client.example.com')
          .get('/request')
          .reply(200, request);

          return this.wrap({
            agent: this.agent,
            route,
            verb,
            auth: {
              request_uri: `https://client.example.com/request#${Date.now()}`,
              scope: 'openid',
              client_id: 'client',
              response_type: 'code'
            }
          })
        .expect(302)
        .expect((response) => {
          const expected = parse('https://client.example.com/cb', true);
          const actual = parse(response.headers.location, true);
          ['protocol', 'host', 'pathname'].forEach((attr) => {
            expect(actual[attr]).to.equal(expected[attr]);
          });
          expect(actual.query).to.have.property('code');
        });
        });
      });

      context('caching of the request_uris', function () {
        it('caches the uris', function* () {
          const cache = new RequestUriCache(this.provider);
          nock('https://client.example.com')
          .get('/cachedRequest')
          .reply(200, 'content')
          .get('/cachedRequest')
          .reply(200, 'content2');

          const first = yield cache.resolve('https://client.example.com/cachedRequest#1');
          const second = yield cache.resolve('https://client.example.com/cachedRequest#1');
          const third = yield cache.resolve('https://client.example.com/cachedRequest#2');
          const fourth = yield cache.resolve('https://client.example.com/cachedRequest#2');

          expect(first).to.equal(second);
          expect(first).not.to.equal(third);
          expect(third).to.equal(fourth);
        });

        it('respects provided max-age', function* () {
          const cache = new RequestUriCache(this.provider);
          nock('https://client.example.com')
          .get('/cachedRequest')
          .reply(200, 'content24', {
            'Cache-Control': 'private, max-age=1'
          })
          .get('/cachedRequest')
          .reply(200, 'content82');

          const first = yield cache.resolve('https://client.example.com/cachedRequest');
          yield new Promise((resolve) => {
            setTimeout(() => {
              resolve();
            }, 1050);
          });
          const second = yield cache.resolve('https://client.example.com/cachedRequest');

          expect(first).to.equal('content24');
          expect(second).to.equal('content82');
        });
      });

      it('doesnt allow too long request_uris', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);

        return this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request_uri: 'https://veeeeryloong.com/uri#Lorem&Ipsum&is&simply&dummy&text&of&the&printing&and&typesetting&industry.&Lorem&Ipsum&has&been&the&industrys&standard&dummy&text&ever&since&the&1500s,&when&an&unknown&printer&took&a&galley&of&type&and&scrambled&it&to&make&a&type&specimen&book.&It&has&survived&not&only&five&centuries,&but&also&the&leap&into&electronic&typesetting,&remaining&essentially&unchanged.&It&was&popularised&in&the&1960s&with&the&release&of&Letraset&sheets&containing&Lorem&Ipsum&passages,&and&more&recently&with&desktop&publishing&software&like&Aldus&PageMaker&including&versions&of&Lorem&Ipsum',
            scope: 'openid',
            client_id: 'client',
            response_type: 'code'
          }
        })
      .expect(302)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
        expect(spy.args[0][0]).to.have.property('message', 'invalid_request_uri');
        expect(spy.args[0][0]).to.have.property('error_description',
          'the request_uri MUST NOT exceed 512 characters');
      });
      });

      context('when client has requestUris set', function () {
        before(function* () {
          (yield this.provider.Client.find('client')).requestUris = ['https://thisoneisallowed.com'];
        });

        after(function* () {
          (yield this.provider.Client.find('client')).requestUris = undefined;
        });

        it('checks the whitelist', function () {
          return JWT.sign({
            client_id: 'client',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb'
          }, null, 'none').then((request) => {
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
                response_type: 'code'
              }
            })
          .expect(302)
          .expect((response) => {
            const expected = parse('https://client.example.com/cb', true);
            const actual = parse(response.headers.location, true);
            ['protocol', 'host', 'pathname'].forEach((attr) => {
              expect(actual[attr]).to.equal(expected[attr]);
            });
            expect(actual.query).to.have.property('code');
          });
          });
        });

        it('allows for fragments to be provided', function () {
          return JWT.sign({
            client_id: 'client',
            response_type: 'code',
            redirect_uri: 'https://client.example.com/cb'
          }, null, 'none').then((request) => {
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
                response_type: 'code'
              }
            })
          .expect(302)
          .expect((response) => {
            const expected = parse('https://client.example.com/cb', true);
            const actual = parse(response.headers.location, true);
            ['protocol', 'host', 'pathname'].forEach((attr) => {
              expect(actual[attr]).to.equal(expected[attr]);
            });
            expect(actual.query).to.have.property('code');
          });
          });
        });

        it('doesnt allow to bypass these', function () {
          const spy = sinon.spy();
          this.provider.once('authorization.error', spy);

          return this.wrap({
            agent: this.agent,
            route,
            verb,
            auth: {
              request_uri: 'https://thisoneisnot.com',
              scope: 'openid',
              client_id: 'client',
              response_type: 'code'
            }
          })
        .expect(302)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(spy.args[0][0]).to.have.property('message', 'invalid_request_uri');
          expect(spy.args[0][0]).to.have.property('error_description',
          'not registered request_uri provided');
        });
        });
      });

      it('doesnt allow slow requests (socket delay)', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);

        nock('https://client.example.com')
        .get('/request')
        .socketDelay(100)
        .reply(200);

        return this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request_uri: `https://client.example.com/request#${Date.now()}`,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code'
          }
        })
      .expect(302)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
        expect(spy.args[0][0]).to.have.property('message', 'invalid_request_uri');
        expect(spy.args[0][0]).to.have.property('error_description').and.matches(/Socket timed out on request to/);
      });
      });

      it.skip('doesnt allow slow requests (response delay)', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);

        nock('https://client.example.com')
        .get('/request')
        .delay(100)
        .reply(200);

        return this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request_uri: `https://client.example.com/request#${Date.now()}`,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code'
          }
        })
      .expect(302)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
        expect(spy.args[0][0]).to.have.property('message', 'invalid_request_uri');
        expect(spy.args[0][0]).to.have.property('error_description').and.matches(/Connection timed out on request to/);
      });
      });

      it('doesnt accepts 200s, rejects even on redirect', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);

        nock('https://client.example.com')
        .get('/request')
        .reply(302, 'redirecting', {
          location: '/someotherrequest'
        });

        return this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request_uri: `https://client.example.com/request#${Date.now()}`,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code'
          }
        })
      .expect(302)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
        expect(spy.args[0][0]).to.have.property('message', 'invalid_request_uri');
        expect(spy.args[0][0]).to.have.property('error_description').and.matches(/expected 200, got 302/);
      });
      });

      it('doesnt allow request inception', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);

        return JWT.sign({
          client_id: 'client',
          response_type: 'code',
          request: 'request inception',
          redirect_uri: 'https://client.example.com/cb'
        }, null, 'none').then((request) => {
          nock('https://client.example.com')
          .get('/request')
          .reply(200, request);
          return this.wrap({
            agent: this.agent,
            route,
            verb,
            auth: {
              request_uri: `https://client.example.com/request#${Date.now()}`,
              scope: 'openid',
              client_id: 'client',
              response_type: 'code'
            }
          })
        .expect(302)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(spy.args[0][0]).to.have.property('message', 'invalid_request_object');
          expect(spy.args[0][0]).to.have.property('error_description',
            'request object must not contain request or request_uri properties');
        });
        });
      });

      it('doesnt allow requestUri inception', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);

        return JWT.sign({
          client_id: 'client',
          response_type: 'code',
          request_uri: 'request uri inception',
          redirect_uri: 'https://client.example.com/cb'
        }, null, 'none').then((request) => {
          nock('https://client.example.com')
          .get('/request')
          .reply(200, request);

          return this.wrap({
            agent: this.agent,
            route,
            verb,
            auth: {
              request_uri: `https://client.example.com/request#${Date.now()}`,
              scope: 'openid',
              client_id: 'client',
              response_type: 'code'
            }
          })
        .expect(302)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(spy.args[0][0]).to.have.property('message', 'invalid_request_object');
          expect(spy.args[0][0]).to.have.property('error_description',
            'request object must not contain request or request_uri properties');
        });
        });
      });

      it('doesnt allow response_type to differ', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);

        return JWT.sign({
          client_id: 'client',
          response_type: 'id_token',
          redirect_uri: 'https://client.example.com/cb'
        }, null, 'none').then((request) => {
          nock('https://client.example.com')
          .get('/request')
          .reply(200, request);

          return this.wrap({
            agent: this.agent,
            route,
            verb,
            auth: {
              request_uri: `https://client.example.com/request#${Date.now()}`,
              scope: 'openid',
              client_id: 'client',
              response_type: 'code'
            }
          })
        .expect(302)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(spy.args[0][0]).to.have.property('message', 'invalid_request_object');
          expect(spy.args[0][0]).to.have.property('error_description',
            'request response_type must equal the one in request parameters');
        });
        });
      });

      it('doesnt allow client_id to differ', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);

        return JWT.sign({
          client_id: 'client2',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb'
        }, null, 'none').then((request) => {
          nock('https://client.example.com')
          .get('/request')
          .reply(200, request);

          return this.wrap({
            agent: this.agent,
            route,
            verb,
            auth: {
              request_uri: `https://client.example.com/request#${Date.now()}`,
              scope: 'openid',
              client_id: 'client',
              response_type: 'code'
            }
          })
        .expect(302)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(spy.args[0][0]).to.have.property('message', 'invalid_request_object');
          expect(spy.args[0][0]).to.have.property('error_description',
            'request client_id must equal the one in request parameters');
        });
        });
      });

      it('handles invalid signed looklike jwts', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);

        nock('https://client.example.com')
        .get('/request')
        .reply(200, 'definitely.notsigned.jwt');

        return this.wrap({
          agent: this.agent,
          route,
          verb,
          auth: {
            request_uri: `https://client.example.com/request#${Date.now()}`,
            scope: 'openid',
            client_id: 'client',
            response_type: 'code'
          }
        })
      .expect(302)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
        expect(spy.args[0][0]).to.have.property('message', 'invalid_request_object');
        expect(spy.args[0][0]).to.have.property('error_description').and.matches(
          /could not parse request_uri as valid JWT/
        );
      });
      });

      it('doesnt allow clients with predefined alg to bypass this alg', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);

        return JWT.sign({
          client_id: 'client-with-HS-sig',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb'
        }, null, 'none').then((request) => {
          nock('https://client.example.com')
          .get('/request')
          .reply(200, request);

          return this.wrap({
            agent: this.agent,
            route,
            verb,
            auth: {
              request_uri: `https://client.example.com/request#${Date.now()}`,
              scope: 'openid',
              client_id: 'client-with-HS-sig',
              response_type: 'code'
            }
          })
        .expect(302)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(spy.args[0][0]).to.have.property('message', 'invalid_request_object');
          expect(spy.args[0][0]).to.have.property('error_description',
            'the preregistered alg must be used in request or request_uri');
        });
        });
      });


      it('bad signatures will be rejected', function* () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);

        const key = (yield this.provider.Client.find('client-with-HS-sig')).keystore.get({ alg: 'HS256' });
        return JWT.sign({
          client_id: 'client',
          response_type: 'code',
          redirect_uri: 'https://client.example.com/cb'
        }, key, 'HS256').then((request) => {
          nock('https://client.example.com')
          .get('/request')
          .reply(200, request);

          return this.wrap({
            agent: this.agent,
            route,
            verb,
            auth: {
              request_uri: `https://client.example.com/request#${Date.now()}`,
              scope: 'openid',
              client_id: 'client',
              response_type: 'code'
            }
          })
        .expect(302)
        .expect(() => {
          expect(spy.calledOnce).to.be.true;
          expect(spy.args[0][0]).to.have.property('message', 'invalid_request_object');
          expect(spy.args[0][0]).to.have.property('error_description').that.matches(
            /could not validate request object signature/
          );
        });
        });
      });
    });
  });
});
