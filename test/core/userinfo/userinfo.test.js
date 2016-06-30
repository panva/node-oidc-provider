'use strict';

const {
  provider, agent, AuthenticationRequest, wrap
} = require('../../test_helper')(__dirname);
const { expect } = require('chai');
const url = require('url');

provider.setupClient();
provider.setupCerts();

describe('userinfo /me', function () {
  before(agent.login);

  before(function () {
    const auth = new AuthenticationRequest({
      response_type: 'id_token token',
      scope: 'openid email'
    });

    return wrap({ agent, auth, verb: 'get', route: '/auth' })
    .expect(auth.validateFragment)
    .expect((response) => {
      const { query } = url.parse(response.headers.location, true);
      this.access_token = query.access_token;
    });
  });

  it('does allow for scopes to be shrunk', function () {
    return agent.get('/me')
      .query({
        scope: 'openid'
      })
      .set('Authorization', `Bearer ${this.access_token}`)
      .expect(200)
      .expect(function (response) {
        expect(response.body).to.have.keys(['sub']);
        expect(response.body).not.to.have.keys(['email', 'email_verified']);
      });
  });

  it('does not allow for scopes to be extended', function () {
    return agent.get('/me')
      .query({
        scope: 'openid profile'
      })
      .set('Authorization', `Bearer ${this.access_token}`)
      .expect(400)
      .expect({ error: 'invalid_scope', scope: 'profile', error_description: 'access token missing requested scope' });
  });
});

describe('userinfo /me WWW-Authenticate header', function () {
  it('is set', function () {
    return agent.get('/me')
    .set('Authorization', 'Bearer ThisIsNotAValidToken')
    .expect(401)
    .expect('WWW-Authenticate', new RegExp(`^Bearer realm="${provider.issuer}"`))
    .expect('WWW-Authenticate', /error="invalid_token"/);
  });
});
