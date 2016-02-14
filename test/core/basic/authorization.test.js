'use strict';

const {
  setupCerts, setupClient, agent, AuthenticationRequest
} = require('../../test_helper')(__dirname);

const route = '/auth';

setupClient();
setupCerts();

describe(`${route} logged in`, function() {
  agent.login();

  it('works', function() {
    const auth = new AuthenticationRequest();

    return agent.get(route)
      .query(auth)
      .expect(302)
      .expect(auth.validatePresence(['code', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation);
  });
});

describe(`${route} logged out`, function() {

  agent.logout();

  it('works', function() {
    const auth = new AuthenticationRequest({
      prompt: 'none'
    });

    return agent.get(route)
      .query(auth)
      .expect(302)
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('login_required'))
      .expect(auth.validateErrorDescription('End-User authentication is required'));
  });
});
