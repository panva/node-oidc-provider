'use strict';

const bootstrap = require('../../test_helper');

const route = '/auth';

['get', 'post'].forEach(verb => {
  describe(`${verb} ${route} response_type=none`, function () {
    const { provider, agent, AuthorizationRequest, wrap } = bootstrap(__dirname);
    provider.setupClient();
    provider.setupCerts();

    before(agent.login);
    after(agent.logout);

    it('responds with a state in search', function () {
      const auth = new AuthorizationRequest({
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
      const auth = new AuthorizationRequest({
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
