/* eslint-disable no-underscore-dangle */

const { parse: parseLocation } = require('url');

const get = require('lodash/get');
const { expect } = require('chai');
const KeyGrip = require('keygrip'); // eslint-disable-line import/no-extraneous-dependencies

const { decode: decodeJWT } = require('../../lib/helpers/jwt');
const bootstrap = require('../test_helper');

const route = '/auth';
const expire = new Date();

expire.setDate(expire.getDate() + 1);

['get', 'post'].forEach((verb) => {
  describe(`claimsParameter via ${verb} ${route}`, () => {
    before(bootstrap(__dirname));

    describe('specify id_token', () => {
      before(function () {
        return this.login({
          claims: {
            id_token: {
              email: null,
              middle_name: {},
            },
          },
        });
      });
      after(function () { return this.logout(); });

      it('should return individual claims requested', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: {
            id_token: {
              email: null,
              middle_name: {},

              preferred_username: 'not returned',
              picture: 1, // not returned
              website: true, // not returned
            },
          },
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token'], false))
          .expect((response) => {
            const { query: { id_token } } = parseLocation(response.headers.location, true);
            const { payload } = decodeJWT(id_token);
            expect(payload).to.contain.keys('email', 'middle_name');
            expect(payload).not.to.have.keys('preferred_username', 'picture', 'website');
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

      it('(pre 4.x behavior backfill) should include the acr claim now', function () {
        const descriptor = Object.getOwnPropertyDescriptor(this.provider.OIDCContext.prototype, 'acr');

        Object.defineProperty(this.provider.OIDCContext.prototype, 'acr', {
          get() {
            return get(this, 'result.login.acr', '0');
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
      before(function () {
        return this.login({
          claims: {
            id_token: {
              email: null,
              middle_name: {},
            },
          },
        });
      });
      after(function () { return this.logout(); });

      it('should return individual claims requested', function (done) {
        const auth = new this.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: {
            userinfo: {
              email: null,
              middle_name: {},

              preferred_username: 'not returned',
              picture: 1, // not returned
              website: true, // not returned
            },
          },
        });

        this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['access_token', 'scope'], false))
          .end((err, response) => {
            if (err) {
              return done(err);
            }

            const { query: { access_token } } = parseLocation(response.headers.location, true);
            return this.agent
              .get('/me')
              .query({ access_token })
              .expect(200)
              .expect(({ body }) => {
                expect(body).to.contain.keys('email', 'middle_name');
                expect(body).not.to.have.keys('preferred_username', 'picture', 'website');
              })
              .end(done);
          });
      });
    });

    describe('specify both id_token and userinfo', () => {
      before(function () {
        return this.login({
          claims: {
            id_token: {
              email: null,
            },
            userinfo: {
              given_name: null,
            },
          },
        });
      });
      after(function () { return this.logout(); });

      it('should return individual claims requested', function (done) {
        const auth = new this.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: {
            id_token: {
              email: null,
            },
            userinfo: {
              given_name: null,
            },
          },
        });

        this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token', 'access_token', 'scope'], false))
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

          const sess = new this.provider.Interaction('resume', {});
          const keys = new KeyGrip(i(this.provider).configuration('cookies.keys'));
          if (grant) {
            const cookie = `_interaction_resume=resume; path=${this.suitePath('/auth/resume')}; expires=${expire.toGMTString()}; httponly`;
            cookies.push(cookie);
            const [pre, ...post] = cookie.split(';');
            cookies.push([`_interaction_resume.sig=${keys.sign(pre)}`, ...post].join(';'));
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

        it('session subject value differs from the one requested [1/2]', function () {
          const session = this.getSession();
          const auth = new this.AuthorizationRequest({
            client_id: 'client',
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            claims: {
              id_token: {
                sub: {
                  value: session.account,
                },
              },
            },
          });

          return this.wrap({ route, verb, auth })
            .expect(302)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['id_token', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation);
        });

        it('session subject value differs from the one requested [2/2]', function () {
          const session = this.getSession();
          const auth = new this.AuthorizationRequest({
            client_id: 'client-pairwise',
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            claims: {
              id_token: {
                sub: {
                  value: `${session.account}-pairwise`,
                },
              },
            },
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
              response_mode: 'fragment',
              scope: 'openid',
              prompt: 'none',
              claims: {
                id_token: {
                  acr: {
                    essential: true,
                    values: ['1', '2'],
                  },
                },
              },
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
              response_mode: 'fragment',
              scope: 'openid',
              prompt: 'none',
              claims: {
                id_token: {
                  acr: {
                    essential: true,
                    value: '1',
                  },
                },
              },
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
        it('session subject value differs from the one requested [1/3]', function () {
          const auth = new this.AuthorizationRequest({
            client_id: 'client',
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            claims: {
              id_token: {
                sub: {
                  value: 'iexpectthisid',
                },
              },
            },
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

        it('session subject value differs from the one requested [2/3]', function () {
          const auth = new this.AuthorizationRequest({
            client_id: 'client-pairwise',
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            claims: {
              id_token: {
                sub: {
                  value: 'iexpectthisid-pairwise',
                },
              },
            },
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

        it('session subject value differs from the one requested [3/3]', function () {
          this.logout();
          const auth = new this.AuthorizationRequest({
            client_id: 'client-pairwise',
            response_type: 'id_token',
            scope: 'openid',
            claims: {
              id_token: {
                sub: {
                  value: 'iexpectthisid-pairwise',
                },
              },
            },
          });

          return this.wrap({ route, verb, auth })
            .expect(302)
            .expect(auth.validateInteractionRedirect)
            .expect(auth.validateInteraction('login', 'claims_id_token_sub_value', 'no_session'));
        });

        it('none of multiple authentication context class references requested are met (1/2)', function () {
          const auth = new this.AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            claims: {
              id_token: {
                acr: {
                  essential: true,
                  values: ['1', '2'],
                },
              },
            },
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

        it('none of multiple authentication context class references requested are met (2/2)', function () {
          const auth = new this.AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            claims: {
              id_token: {
                acr: {
                  essential: true,
                  values: 'foo',
                },
              },
            },
          });

          return this.wrap({ route, verb, auth })
            .expect(302)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['error', 'error_description', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(auth.validateError('invalid_request'))
            .expect(auth.validateErrorDescription('invalid claims.id_token.acr.values type'));
        });

        it('single requested authentication context class reference is not met', function () {
          const auth = new this.AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            claims: {
              id_token: {
                acr: {
                  essential: true,
                  value: '1',
                },
              },
            },
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

        it('additional claims are requested', function () {
          const auth = new this.AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            claims: {
              id_token: { family_name: null },
            },
          });

          return this.wrap({ route, verb, auth })
            .expect(302)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['error', 'error_description', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(auth.validateError('consent_required'))
            .expect(auth.validateErrorDescription('requested claims not granted by End-User'));
        });

        it('id_token_hint belongs to a user that is not currently logged in [1/3]', async function () {
          const client = await this.provider.Client.find('client');
          const { IdToken } = this.provider;
          const idToken = new IdToken({
            sub: 'not-the-droid-you-are-looking-for',
          }, { client, ctx: undefined });

          idToken.scope = 'openid';
          const hint = await idToken.issue({ use: 'idtoken' });

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

        it('id_token_hint belongs to a user that is not currently logged in [2/3]', async function () {
          const client = await this.provider.Client.find('client-pairwise');
          const { IdToken } = this.provider;
          const idToken = new IdToken({
            sub: 'not-the-droid-you-are-looking-for',
          }, { client, ctx: undefined });

          idToken.scope = 'openid';
          const hint = await idToken.issue({ use: 'idtoken' });

          const auth = new this.AuthorizationRequest({
            client_id: 'client-pairwise',
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

        it('id_token_hint belongs to a user that is not currently logged in [3/3]', async function () {
          this.logout();
          const client = await this.provider.Client.find('client-pairwise');
          const { IdToken } = this.provider;
          const idToken = new IdToken({
            sub: 'not-the-droid-you-are-looking-for',
          }, { client, ctx: undefined });

          idToken.scope = 'openid';
          const hint = await idToken.issue({ use: 'idtoken' });

          const auth = new this.AuthorizationRequest({
            client_id: 'client-pairwise',
            response_type: 'id_token',
            scope: 'openid',
            id_token_hint: hint,
          });

          return this.wrap({ route, verb, auth })
            .expect(302)
            .expect(auth.validateInteractionRedirect)
            .expect(auth.validateInteraction('login', 'id_token_hint', 'no_session'));
        });

        it('id_token_hint belongs to a user that is currently logged in [1/2]', async function () {
          const session = this.getSession();
          const client = await this.provider.Client.find('client');
          const { IdToken } = this.provider;
          const idToken = new IdToken({ sub: session.account }, { client, ctx: undefined });

          idToken.scope = 'openid';
          const hint = await idToken.issue({ use: 'idtoken' });

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

        it('id_token_hint belongs to a user that is currently logged in [2/2]', async function () {
          const session = this.getSession();
          const client = await this.provider.Client.find('client-pairwise');
          const { IdToken } = this.provider;
          const idToken = new IdToken({ sub: session.account }, { client, ctx: undefined });

          idToken.scope = 'openid';
          const hint = await idToken.issue({ use: 'idtoken' });

          const auth = new this.AuthorizationRequest({
            client_id: 'client-pairwise',
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

      describe('when userinfo is disabled', () => {
        before(function () {
          i(this.provider).configuration('features').userinfo.enabled = false;
        });

        after(function () {
          i(this.provider).configuration('features').userinfo.enabled = false;
        });

        it('should not accept userinfo as a property', function () {
          const auth = new this.AuthorizationRequest({
            response_type: 'id_token token',
            scope: 'openid',
            claims: {
              userinfo: {
                email: null,
                middle_name: {},
              },
            },
          });

          return this.wrap({ route, verb, auth })
            .expect(302)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['error', 'error_description', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(auth.validateError('invalid_request'))
            .expect(auth.validateErrorDescription('claims.userinfo should not be used since userinfo endpoint is not supported'));
        });
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
