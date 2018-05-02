/* eslint-disable no-underscore-dangle */

const bootstrap = require('../test_helper');
const { get } = require('lodash');
const { parse: parseLocation } = require('url');
const { decode: decodeJWT } = require('../../lib/helpers/jwt');
const { expect } = require('chai');

const j = JSON.stringify;
const route = '/auth';
const expire = new Date();
const KeyGrip = require('keygrip'); // eslint-disable-line import/no-extraneous-dependencies

expire.setDate(expire.getDate() + 1);

['get', 'post'].forEach((verb) => {
  describe(`claimsParameter via ${verb} ${route}`, () => {
    before(bootstrap(__dirname)); // provider, AuthorizationRequest, getSession, wrap

    describe('specify id_token', () => {
      before(function () { return this.login(); });
      after(function () { return this.logout(); });

      it('should return individual claims requested', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: j({
            id_token: {
              email: null, // returned
              family_name: { essential: true }, // returned
              gender: { essential: false }, // returned
              given_name: { value: 'John' }, // returned
              locale: { values: ['en-US', 'en-GB'] }, // returned
              middle_name: {}, // not returned
              preferred_username: 'not returned',
              picture: 1, // not returned
              website: true, // not returned
            },
          }),
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token'], false))
          .expect((response) => {
            const { query: { id_token } } = parseLocation(response.headers.location, true);
            const { payload } = decodeJWT(id_token);
            expect(payload).to.contain.keys('email', 'family_name', 'gender', 'given_name', 'locale');
            expect(payload).not.to.have.keys('middle_name', 'preferred_username', 'picture', 'website');
          });
      });
    });

    describe('with acr_values on the client', () => {
      before(function () { return this.login(); });
      after(function () { return this.logout(); });

      before(async function () {
        const client = await this.provider.Client.find('client');
        client.defaultAcrValues = ['1', '2'];
      });

      after(async function () {
        const client = await this.provider.Client.find('client');
        delete client.defaultAcrValues;
      });

      it('(pre 3.x behavior backfill) should include the acr claim now', function () {
        const descriptor = Object.getOwnPropertyDescriptor(this.provider.OIDCContext.prototype, 'acr');

        Object.defineProperty(this.provider.OIDCContext.prototype, 'acr', {
          get() {
            return get(this, 'result.login.acr', 'session');
          },
        });

        const auth = new this.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
        });

        return this.wrap({ route, verb, auth })
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token'], false))
          .expect((response) => {
            const { query: { id_token } } = parseLocation(response.headers.location, true);
            const { payload } = decodeJWT(id_token);
            expect(payload).to.contain.keys('acr');
            Object.defineProperty(this.provider.OIDCContext.prototype, 'acr', descriptor);
          })
          .catch((err) => {
            Object.defineProperty(this.provider.OIDCContext.prototype, 'acr', descriptor);
            throw err;
          });
      });
    });

    describe('specify userinfo', () => {
      before(function () { return this.login(); });
      after(function () { return this.logout(); });

      it('should return individual claims requested', function (done) {
        const auth = new this.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: j({
            userinfo: {
              email: null, // returned
              family_name: { essential: true }, // returned
              gender: { essential: false }, // returned
              given_name: { value: 'John' }, // returned
              locale: { values: ['en-US', 'en-GB'] }, // returned
              middle_name: {}, // not returned
            },
          }),
        });

        this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['access_token'], false))
          .end((err, response) => {
            if (err) {
              return done(err);
            }

            const { query: { access_token } } = parseLocation(response.headers.location, true);
            return this.agent
              .get('/me')
              .query({ access_token })
              .expect(200)
              .expect((userinfo) => {
                expect(userinfo.body).to.contain.keys('email', 'family_name', 'gender', 'given_name', 'locale');
                expect(userinfo.body).not.to.have.key('middle_name');
              })
              .end(done);
          });
      });
    });

    describe('specify both id_token and userinfo', () => {
      before(function () { return this.login(); });
      after(function () { return this.logout(); });

      it('should return individual claims requested', function (done) {
        const auth = new this.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: j({
            id_token: {
              email: null,
            },
            userinfo: {
              given_name: null,
            },
          }),
        });

        this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token', 'access_token'], false))
          .expect((response) => {
            const { query: { id_token } } = parseLocation(response.headers.location, true);
            const { payload } = decodeJWT(id_token);
            expect(payload).to.contain.key('email');
            expect(payload).not.to.have.key('given_name');
          })
          .end((err, response) => {
            const { query: { access_token } } = parseLocation(response.headers.location, true);
            this.agent
              .get('/me')
              .query({ access_token })
              .expect(200)
              .expect((userinfo) => {
                expect(userinfo.body).to.contain.key('given_name');
                expect(userinfo.body).not.to.have.key('email');
              })
              .end(done);
          });
      });
    });

    describe('related interactions', () => {
      beforeEach(function () { return this.login(); });
      afterEach(function () { return this.logout(); });
      context('are met', () => {
        function setup(grant, result) {
          const cookies = [];

          const sess = new this.provider.Session('resume', {});
          const keys = new KeyGrip(i(this.provider).configuration('cookies.keys'));
          if (grant) {
            const cookie = `_grant=resume; path=/auth/resume; expires=${expire.toGMTString()}; httponly`;
            cookies.push(cookie);
            const [pre, ...post] = cookie.split(';');
            cookies.push([`_grant.sig=${keys.sign(pre)}`, ...post].join(';'));
            Object.assign(sess, { params: grant });
          }

          if (result) {
            Object.assign(sess, { result });
          }

          this.agent._saveCookies.bind(this.agent)({
            headers: {
              'set-cookie': cookies,
            },
          });

          return sess.save();
        }

        it('session subject value differs from the one requested', function () {
          const session = this.getSession();
          const auth = new this.AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            claims: j({
              id_token: {
                sub: {
                  value: session.account,
                },
              },
            }),
          });

          return this.wrap({ route, verb, auth })
            .expect(302)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['id_token', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation);
        });

        if (verb === 'get') {
          it('none of multiple authentication context class references requested are met', function () {
            const auth = new this.AuthorizationRequest({
              response_type: 'id_token',
              scope: 'openid',
              prompt: 'none',
              claims: j({
                id_token: {
                  acr: {
                    essential: true,
                    values: ['1', '2'],
                  },
                },
              }),
            });

            setup.call(this, auth, {
              login: {
                account: this.loggedInAccountId,
                acr: '2',
              },
            });

            return this.wrap({ route: `${route}/resume`, verb, auth })
              .expect(302)
              .expect(auth.validateFragment)
              .expect(auth.validatePresence(['id_token', 'state']))
              .expect(auth.validateState)
              .expect(auth.validateClientLocation);
          });

          it('single requested authentication context class reference is not met', function () {
            const auth = new this.AuthorizationRequest({
              response_type: 'id_token',
              scope: 'openid',
              prompt: 'none',
              claims: j({
                id_token: {
                  acr: {
                    essential: true,
                    value: '1',
                  },
                },
              }),
            });

            setup.call(this, auth, {
              login: {
                account: this.loggedInAccountId,
                acr: '1',
              },
            });

            return this.wrap({ route: `${route}/resume`, verb, auth })
              .expect(302)
              .expect(auth.validateFragment)
              .expect(auth.validatePresence(['id_token', 'state']))
              .expect(auth.validateState)
              .expect(auth.validateClientLocation);
          });
        }
      });

      context('are not met', () => {
        it('session subject value differs from the one requested', function () {
          const auth = new this.AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            claims: j({
              id_token: {
                sub: {
                  value: 'iexpectthisid',
                },
              },
            }),
          });

          return this.wrap({ route, verb, auth })
            .expect(302)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['error', 'error_description', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(auth.validateError('login_required'))
            .expect(auth.validateErrorDescription('requested subject could not be obtained'));
        });

        it('none of multiple authentication context class references requested are met', function () {
          const auth = new this.AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            claims: j({
              id_token: {
                acr: {
                  essential: true,
                  values: ['1', '2'],
                },
              },
            }),
          });

          return this.wrap({ route, verb, auth })
            .expect(302)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['error', 'error_description', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(auth.validateError('login_required'))
            .expect(auth.validateErrorDescription('none of the requested ACRs could not be obtained'));
        });

        it('single requested authentication context class reference is not met', function () {
          const auth = new this.AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            claims: j({
              id_token: {
                acr: {
                  essential: true,
                  value: '1',
                },
              },
            }),
          });

          return this.wrap({ route, verb, auth })
            .expect(302)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['error', 'error_description', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(auth.validateError('login_required'))
            .expect(auth.validateErrorDescription('requested ACR could not be obtained'));
        });

        it('id_token_hint belongs to a user that is not currently logged in', async function () {
          const client = await this.provider.Client.find('client');
          const { IdToken } = this.provider;
          const idToken = new IdToken({
            sub: 'not-the-droid-you-are-looking-for',
          });

          idToken.scope = 'openid';
          const hint = await idToken.sign(client);

          const auth = new this.AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            id_token_hint: hint,
          });

          return this.wrap({ route, verb, auth })
            .expect(302)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['error', 'error_description', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(auth.validateError('login_required'))
            .expect(auth.validateErrorDescription('id_token_hint and authenticated subject do not match'));
        });

        it('id_token_hint belongs to a user that is currently logged in', async function () {
          const session = this.getSession();
          const client = await this.provider.Client.find('client');
          const { IdToken } = this.provider;
          const idToken = new IdToken({
            sub: session.account,
          });

          idToken.scope = 'openid';
          const hint = await idToken.sign(client);

          const auth = new this.AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            id_token_hint: hint,
          });

          return this.wrap({ route, verb, auth })
            .expect(302)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['id_token', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation);
        });
      });
    });

    describe('parameter validations', () => {
      it('should not be combined with response_type=none', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'none',
          scope: 'openid',
          claims: 'something',
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('claims parameter should not be combined with response_type none'));
      });

      it('should handle when invalid json is provided', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: 'something',
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('could not parse the claims parameter JSON'));
      });

      it('should validate an object is passed', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: 'true',
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('claims parameter should be a JSON object'));
      });

      it('should check accepted properties being present', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: '{"not_recognized": "does not matter"}',
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('claims parameter should have userinfo or id_token properties'));
      });

      it('should check userinfo property being a simple object', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: '{"userinfo": "Not an Object"}',
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('claims.userinfo should be an object'));
      });

      it('should check id_token property being a simple object', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: '{"id_token": "Not an Object"}',
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('claims.id_token should be an object'));
      });

      it('should check that userinfo claims are not specified for id_token requests', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'id_token',
          scope: 'openid',
          claims: '{"userinfo": {}}',
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('claims.userinfo should not be used if access_token is not issued'));
      });
    });
  });
});
