const { parse } = require('url');

const { expect } = require('chai');

const bootstrap = require('../test_helper');

const route = '/auth';

describe('session management', () => {
  before(bootstrap(__dirname));

  ['get', 'post'].forEach((verb) => {
    describe(`[session_management] ${verb} ${route} with session`, () => {
      describe('success responses', () => {
        before(function () { return this.login(); });
        it('provides session_state in the response', async function () {
          const auth = new this.AuthorizationRequest({
            response_type: 'code',
            scope: 'openid',
          });

          let sessionState;
          await this.wrap({ route, verb, auth })
            .expect(302)
            .expect(auth.validatePresence(['code', 'state', 'session_state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(({ headers: { location } }) => {
              sessionState = parse(location, true).query.session_state;
            });

          await this.wrap({ route, verb, auth })
            .expect(302)
            .expect(auth.validatePresence(['code', 'state', 'session_state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(({ headers: { location } }) => {
              expect(parse(location, true).query.session_state).to.equal(sessionState);
            });
        });

        bootstrap.passInteractionChecks('native_client_prompt', () => {
          it('doesn\'t omit the session_state for native applications', function () {
            const auth = new this.AuthorizationRequest({
              client_id: 'client-native-claimed',
              response_type: 'code',
              scope: 'openid',
              code_challenge_method: 'S256',
              code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
            });

            return this.wrap({ route, verb, auth })
              .expect(302)
              .expect(auth.validatePresence(['code', 'state', 'session_state']))
              .expect(auth.validateState)
              .expect(auth.validateClientLocation);
          });
        });

        it('sets a _state.clientId cookies', function () {
          const auth = new this.AuthorizationRequest({
            response_type: 'code',
            scope: 'openid',
          });

          return this.wrap({ route, verb, auth })
            .expect(() => {
              const state = this.agent.jar.getCookie('_state.client', { path: '/' });
              expect(state).to.be.ok;
            });
        });
      });

      describe('error responses', () => {
        before(function () { return this.logout(); });

        it('provides salted session_state in the response', async function () {
          const auth = new this.AuthorizationRequest({
            prompt: 'none',
            response_type: 'code',
            scope: 'openid',
          });

          let sessionState;
          await this.wrap({ route, verb, auth })
            .expect(302)
            .expect(auth.validatePresence(['error', 'error_description', 'session_state', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(({ headers: { location } }) => {
              sessionState = parse(location, true).query.session_state;
              expect(sessionState).to.contain('.');
            });

          await this.wrap({ route, verb, auth })
            .expect(302)
            .expect(auth.validatePresence(['error', 'error_description', 'session_state', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(({ headers: { location } }) => {
              expect(parse(location, true).query.session_state).not.to.equal(sessionState);
            });
        });

        it('doesn\'t omit the session_state for native applications', function () {
          const auth = new this.AuthorizationRequest({
            prompt: 'none',
            client_id: 'client-native-claimed',
            response_type: 'code',
            scope: 'openid',
            code_challenge_method: 'S256',
            code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
          });

          return this.wrap({ route, verb, auth })
            .expect(302)
            .expect(auth.validatePresence(['error', 'error_description', 'state', 'session_state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation);
        });

        it('sets a _state.clientId cookies', function () {
          const auth = new this.AuthorizationRequest({
            prompt: 'none',
            response_type: 'code',
            scope: 'openid',
          });

          return this.wrap({ route, verb, auth })
            .expect(() => {
              const state = this.agent.jar.getCookie('_state.client', { path: '/' });
              expect(state).to.be.ok;
            });
        });
      });
    });
  });
});
