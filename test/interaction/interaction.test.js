'use strict';

const { v4: uuid } = require('node-uuid');
const {
  provider,
  agent,
  getSession,
  AuthorizationRequest,
} = require('../test_helper')(__dirname);

const expire = new Date();
expire.setDate(expire.getDate() + 1);

const j = JSON.stringify;
const { expect } = require('chai');

provider.setupClient();
provider.setupCerts();

provider.configuration('prompts').push('custom');

function setup(grant, results) {
  const cookies = [];

  if (grant) {
    cookies.push(`_grant=${j(grant)}; path=/; expires=${expire.toGMTString()}; httponly`);
  }

  if (results) {
    cookies.push(`_grant_result=${j(results)}; path=/; expires=${expire.toGMTString()}; httponly`);
  }

  agent.saveCookies({
    headers: {
      'set-cookie': cookies
    },
  });
}

describe('resume after interaction', function () {
  context('general', function () {
    it('needs the results to be present, else renders an err', function () {
      return agent.get(`/auth/${uuid()}`)
        .expect(400)
        .expect(/authorization request has expired/);
    });
  });

  context('login results', function () {
    it('should redirect to client with error if interaction did not resolve in a session', function () {
      const auth = new AuthorizationRequest({
        response_type: 'code',
        scope: 'openid'
      });

      setup(auth);

      return agent.get(`/auth/${uuid()}`)
        .expect(302)
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('login_required'))
        .expect(auth.validateErrorDescription('End-User authentication is required'));
    });

    it('should process newly established permanent sessions', function () {
      const auth = new AuthorizationRequest({
        response_type: 'code',
        scope: 'openid'
      });

      setup(auth, {
        login: {
          account: uuid(),
          remember: true
        }
      });

      return agent.get(`/auth/${uuid()}`)
        .expect(302)
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validatePresence(['code', 'state']))
        .expect(function () {
          expect(getSession(agent)).to.be.ok;
        });
    });

    it('should process newly established temporary sessions', function () {
      const auth = new AuthorizationRequest({
        response_type: 'code',
        scope: 'openid'
      });

      setup(auth, {
        login: {
          account: uuid()
        }
      });

      return agent.get(`/auth/${uuid()}`)
        .expect(302)
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validatePresence(['code', 'state']))
        .expect(function () {
          expect(getSession(agent)).to.be.undefined;
        });
    });
  });

  context('consent results', function () {
    it('when scope includes offline_access', function () {
      const auth = new AuthorizationRequest({
        response_type: 'code',
        prompt: 'consent',
        scope: 'openid offline_access'
      });

      setup(auth, {
        login: {
          account: uuid(),
          remember: true
        },
        consent: {}
      });

      let authorizationCode;

      provider.once('token.issued', function (code) {
        authorizationCode = code;
      });

      return agent.get(`/auth/${uuid()}`)
        .expect(function () {
          provider.removeAllListeners('token.issued');
        })
        .expect(function () {
          expect(authorizationCode).to.be.ok;
          expect(authorizationCode).to.have.property('scope', 'openid offline_access');
        });
    });

    it('should use the consents from resume cookie if provided', function () {
      const auth = new AuthorizationRequest({
        response_type: 'code',
        scope: 'openid'
      });

      setup(auth, {
        login: {
          account: uuid(),
          remember: true
        },
        consent: {
          scope: 'openid profile'
        }
      });

      let authorizationCode;

      provider.once('token.issued', function (code) {
        authorizationCode = code;
      });

      return agent.get(`/auth/${uuid()}`)
        .expect(function () {
          provider.removeAllListeners('token.issued');
        })
        .expect(function () {
          expect(authorizationCode).to.be.ok;
          expect(authorizationCode).to.have.property('scope', 'openid profile');
        });
    });
  });

  context('custom prompts', function () {
    before(agent.login);
    after(agent.logout);

    it('should fail if they are not resolved', function () {
      const auth = new AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
        prompt: 'custom'
      });

      setup(auth);

      return agent.get(`/auth/${uuid()}`)
        .expect(302)
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('interaction_required'))
        .expect(auth.validateErrorDescription('prompt custom was not resolved'));
    });
  });
});
