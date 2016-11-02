'use strict';

const bootstrap = require('../test_helper');
const { expect } = require('chai');

const route = '/auth';

describe('session management', function () {
  before(bootstrap(__dirname)); // provider, agent, this.AuthorizationRequest, wrap

  ['get', 'post'].forEach((verb) => {
    describe(`[session_management] ${verb} ${route} with session`, function () {
      before(function () { return this.login(); });

      it('provides session_state in the response', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid'
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
          scope: 'openid'
        });

        return this.wrap({ route, verb, auth })
      .expect(() => {
        const state = this.agent.jar.getCookie('_state.client', { path: '/' });
        expect(state).to.be.ok;
      });
      });
    });

    describe('[session_management] check_session_iframe', function () {
      it('responds with frameable html', function () {
        return this.agent.get('/session/check')
    .expect(200)
    .expect('content-type', /text\/html/);
      });
    });
  });
});
