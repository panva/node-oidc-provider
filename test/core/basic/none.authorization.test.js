'use strict';

const bootstrap = require('../../test_helper');

const route = '/auth';

['get', 'post'].forEach((verb) => {
  describe(`${verb} ${route} response_type=none`, function () {
    before(bootstrap(__dirname)); // provider, agent, AuthorizationRequest, wrap

    before(function () { return this.login(); });
    after(function () { return this.logout(); });

    it('responds with a state in search', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'none',
        scope: 'openid'
      });

      return this.wrap({ route, verb, auth })
      .expect(302)
      .expect(auth.validatePresence(['state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation);
    });

    it('responds with a state in fragment', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'none',
        response_mode: 'fragment',
        scope: 'openid'
      });

      return this.wrap({ route, verb, auth })
      .expect(302)
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation);
    });
  });
});
