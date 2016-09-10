'use strict';

const bootstrap = require('../test_helper');
const { expect } = require('chai');

const route = '/auth';

describe('session management', () => {
  const { provider, agent, AuthorizationRequest, wrap } = bootstrap(__dirname);
  provider.setupClient();


  ['get', 'post'].forEach(verb => {
    describe(`[session_management] ${verb} ${route} with session`, () => {
      before(agent.login);

      it('provides session_state in the response', () => {
        const auth = new AuthorizationRequest({
          response_type: 'code',
          scope: 'openid'
        });

        return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(auth.validatePresence(['session_state'], false))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation);
      });

      it('sets a _session_states cookie with the clientId as keys', () => {
        const auth = new AuthorizationRequest({
          response_type: 'code',
          scope: 'openid'
        });

        return wrap({ agent, route, verb, auth })
      .expect(() => {
        const states = agent.jar.getCookie('_session_states', { path: '/' });
        expect(states).to.be.ok;
        expect(JSON.parse(states.value)).to.have.key('client');
      });
      });
    });

    describe('[session_management] check_session_iframe', () => {
      it('responds with frameable html', () => {
        return agent.get('/session/check')
    .expect(200)
    .expect('content-type', /text\/html/);
      });
    });
  });
});
