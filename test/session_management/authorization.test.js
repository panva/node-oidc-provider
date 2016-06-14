'use strict';

const {
  provider, agent, AuthenticationRequest, wrap
} = require('../test_helper')(__dirname);

const route = '/auth';

provider.setupClient();
provider.setupCerts();

['get', 'post'].forEach((verb) => {
  describe(`[session_management] ${verb} ${route} with session`, function () {
    before(agent.login);

    it('provides session_state in the response', function () {
      const auth = new AuthenticationRequest({
        response_type: 'code',
        scope: 'openid'
      });

      return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(auth.validatePresence(['session_state'], false))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation);
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
