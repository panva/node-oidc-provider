'use strict';

const {
  provider, agent, AuthenticationRequest, wrap
} = require('../../test_helper')(__dirname);

const route = '/auth';

provider.setupClient();
provider.setupCerts();

['get', 'post'].forEach((verb) => {
  describe(`${verb} ${route} response_type=none`, function () {
    before(agent.login);
    after(agent.logout);

    it('responds with a state in search', function () {
      const auth = new AuthenticationRequest({
        response_type: 'none',
        scope: 'openid'
      });

      return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(auth.validatePresence(['state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation);
    });

    it('responds with a state in fragment', function () {
      const auth = new AuthenticationRequest({
        response_type: 'none',
        response_mode: 'fragment',
        scope: 'openid'
      });

      return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation);
    });
  });
});
