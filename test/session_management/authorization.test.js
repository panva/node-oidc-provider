const { expect } = require('chai');

const bootstrap = require('../test_helper');

const route = '/auth';

describe('session management', () => {
  before(bootstrap(__dirname));

  ['get', 'post'].forEach((verb) => {
    describe(`[session_management] ${verb} ${route} with session`, () => {
      before(function () { return this.login(); });

      it('provides session_state in the response', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validatePresence(['session_state'], false))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);
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
  });
});
