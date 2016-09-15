'use strict';

const bootstrap = require('../test_helper');
const { parse: parseLocation } = require('url');
const { decode: decodeJWT } = require('../../lib/helpers/jwt');
const { expect } = require('chai');

const j = JSON.stringify;
const route = '/auth';

['get', 'post'].forEach((verb) => {
  describe(`claimsParameter via ${verb} ${route}`, () => {
    const { provider, agent, AuthorizationRequest, getSession, wrap } = bootstrap(__dirname);
    provider.setupClient();

    describe('specify id_token', () => {
      before(agent.login);
      after(agent.logout);

      it('should return individual claims requested', () => {
        const auth = new AuthorizationRequest({
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
            }
          })
        });

        return wrap({ agent, route, verb, auth })
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
      before(agent.login);
      after(agent.logout);

      before(function* () {
        const client = yield provider.Client.find('client');
        client.defaultAcrValues = ['1', '2'];
      });

      after(function* () {
        const client = yield provider.Client.find('client');
        delete client.defaultAcrValues;
      });

      it('should include the acr claim now', () => {
        const auth = new AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid'
        });

        return wrap({ agent, route, verb, auth })
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['id_token'], false))
        .expect((response) => {
          const { query: { id_token } } = parseLocation(response.headers.location, true);
          const { payload } = decodeJWT(id_token);
          expect(payload).to.contain.keys('acr');
        });
      });
    });

    describe('specify userinfo', () => {
      before(agent.login);
      after(agent.logout);

      it('should return individual claims requested', (done) => {
        const auth = new AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: j({
            userinfo: {
              email: null, // returned
              family_name: { essential: true }, // returned
              gender: { essential: false }, // returned
              given_name: { value: 'John' }, // returned
              locale: { values: ['en-US', 'en-GB'] }, // returned
              middle_name: {} // not returned
            }
          })
        });

        wrap({ agent, route, verb, auth })
        .expect(302)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['access_token'], false))
        .end((err, response) => {
          if (err) {
            return done(err);
          }

          const { query: { access_token } } = parseLocation(response.headers.location, true);
          return agent
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
      before(agent.login);
      after(agent.logout);

      it('should return individual claims requested', (done) => {
        const auth = new AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: j({
            id_token: {
              email: null
            },
            userinfo: {
              given_name: null
            }
          })
        });

        wrap({ agent, route, verb, auth })
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
          agent
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
      beforeEach(agent.login);
      afterEach(agent.logout);
      context('are met', () => {
        it('session subject value differs from the one requested', () => {
          const session = getSession(agent);
          const auth = new AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            claims: j({
              id_token: {
                sub: {
                  value: session.account
                }
              }
            })
          });

          return wrap({ agent, route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);
        });

        it('none of multiple authentication context class references requested are met', () => {
          const session = getSession(agent);
          session.acrValue = '2';
          const auth = new AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            claims: j({
              id_token: {
                acr: {
                  essential: true,
                  values: ['1', '2']
                }
              }
            })
          });

          return wrap({ agent, route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);
        });

        it('single requested authentication context class reference is not met', () => {
          const session = getSession(agent);
          session.acrValue = '1';
          const auth = new AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            claims: j({
              id_token: {
                acr: {
                  essential: true,
                  value: '1'
                }
              }
            })
          });

          return wrap({ agent, route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);
        });
      });

      context('are not met', () => {
        it('session subject value differs from the one requested', () => {
          const auth = new AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            claims: j({
              id_token: {
                sub: {
                  value: 'iexpectthisid'
                }
              }
            })
          });

          return wrap({ agent, route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('login_required'))
          .expect(auth.validateErrorDescription('requested subject could not be obtained'));
        });

        it('none of multiple authentication context class references requested are met', () => {
          const auth = new AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            claims: j({
              id_token: {
                acr: {
                  essential: true,
                  values: ['1', '2']
                }
              }
            })
          });

          return wrap({ agent, route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('login_required'))
          .expect(auth.validateErrorDescription('none of the requested ACRs could not be obtained'));
        });

        it('single requested authentication context class reference is not met', () => {
          const auth = new AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            claims: j({
              id_token: {
                acr: {
                  essential: true,
                  value: '1'
                }
              }
            })
          });

          return wrap({ agent, route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('login_required'))
          .expect(auth.validateErrorDescription('requested ACR could not be obtained'));
        });

        it('id_token_hint belongs to a user that is not currently logged in', function* () {
          const client = yield provider.Client.find('client');
          const IdToken = provider.IdToken;
          const idToken = new IdToken({
            sub: 'not-the-droid-you-are-looking-for'
          });

          idToken.scope = 'openid';
          const hint = yield idToken.sign(client);

          const auth = new AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            id_token_hint: hint
          });

          return wrap({ agent, route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('login_required'))
          .expect(auth.validateErrorDescription('id_token_hint and authenticated subject do not match'));
        });

        it('id_token_hint belongs to a user that is currently logged in', function* () {
          const session = getSession(agent);
          const client = yield provider.Client.find('client');
          const IdToken = provider.IdToken;
          const idToken = new IdToken({
            sub: session.account
          });

          idToken.scope = 'openid';
          const hint = yield idToken.sign(client);

          const auth = new AuthorizationRequest({
            response_type: 'id_token',
            scope: 'openid',
            prompt: 'none',
            id_token_hint: hint
          });

          return wrap({ agent, route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);
        });
      });
    });

    describe('parameter validations', () => {
      it('should not be combined with response_type=none', () => {
        const auth = new AuthorizationRequest({
          response_type: 'none',
          scope: 'openid',
          claims: 'something'
        });

        return wrap({ agent, route, verb, auth })
        .expect(302)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_request'))
        .expect(auth.validateErrorDescription('claims parameter should not be combined with response_type none'));
      });

      it('should handle when invalid json is provided', () => {
        const auth = new AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: 'something'
        });

        return wrap({ agent, route, verb, auth })
        .expect(302)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_request'))
        .expect(auth.validateErrorDescription('could not parse the claims parameter JSON'));
      });

      it('should validate an object is passed', () => {
        const auth = new AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: 'true'
        });

        return wrap({ agent, route, verb, auth })
        .expect(302)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_request'))
        .expect(auth.validateErrorDescription('claims parameter should be a JSON object'));
      });

      it('should check accepted properties being present', () => {
        const auth = new AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: '{"not_recognized": "does not matter"}'
        });

        return wrap({ agent, route, verb, auth })
        .expect(302)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_request'))
        .expect(auth.validateErrorDescription('claims parameter should have userinfo or id_token properties'));
      });

      it('should check userinfo property being a simple object', () => {
        const auth = new AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: '{"userinfo": "Not an Object"}'
        });

        return wrap({ agent, route, verb, auth })
        .expect(302)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_request'))
        .expect(auth.validateErrorDescription('claims.userinfo should be an object'));
      });

      it('should check id_token property being a simple object', () => {
        const auth = new AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          claims: '{"id_token": "Not an Object"}'
        });

        return wrap({ agent, route, verb, auth })
        .expect(302)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_request'))
        .expect(auth.validateErrorDescription('claims.id_token should be an object'));
      });

      it('should check that userinfo claims are not specified for id_token requests', () => {
        const auth = new AuthorizationRequest({
          response_type: 'id_token',
          scope: 'openid',
          claims: '{"userinfo": {}}'
        });

        return wrap({ agent, route, verb, auth })
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
