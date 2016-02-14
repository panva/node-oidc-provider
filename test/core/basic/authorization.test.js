'use strict';

const {
  provider, agent, AuthenticationRequest
} = require('../../test_helper')(__dirname);

const route = '/auth';

provider.setupClient();
provider.setupCerts();

describe(`${route} with session`, function() {
  agent.login();

  it('responds with a code in search', function() {
    const auth = new AuthenticationRequest({
      response_type: 'code',
      scope: 'openid'
    });

    return agent.get(route)
      .query(auth)
      .expect(302)
      .expect(auth.validatePresence(['code', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation);
  });

  it('responds with a code in fragment', function() {
    const auth = new AuthenticationRequest({
      response_type: 'code',
      response_mode: 'fragment',
      scope: 'openid'
    });

    return agent.get(route)
      .query(auth)
      .expect(302)
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['code', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation);
  });
});

describe(`${route} without session`, function() {

  agent.logout();

  it('redirects back to client when prompt=none', function() {
    const auth = new AuthenticationRequest({
      response_type: 'code',
      scope: 'openid',
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
