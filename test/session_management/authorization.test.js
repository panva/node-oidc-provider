'use strict';

const {
  provider, agent, AuthorizationRequest, wrap
} = require('../test_helper')(__dirname);
const { expect } = require('chai');

const route = '/auth';

provider.setupClient();
provider.setupCerts();

['get', 'post'].forEach((verb) => {
  describe(`[session_management] ${verb} ${route} with session`, function () {
    before(agent.login);

    it('provides session_state in the response', function () {
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

    it('sets a _session_states cookie with the clientId as keys', function () {
      const auth = new AuthorizationRequest({
        response_type: 'code',
        scope: 'openid'
      });

      return wrap({ agent, route, verb, auth })
      .expect(function () {
        const states = agent.jar.getCookie('_session_states', { path: '/' });
        expect(states).to.be.ok;
        expect(JSON.parse(states.value)).to.have.key('client');
      });
    });
  });
});

describe('[session_management] check_session_iframe', function () {
  it('responds with frameable html', function () {
    return agent.get('/session/check')
    .expect(200)
    .expect('content-type', /text\/html/);
  });
});
