'use strict';

const {
  provider, agent, AuthenticationRequest
} = require('../../test_helper')(__dirname);
const sinon = require('sinon');
const { expect } = require('chai');

const route = '/auth';

provider.setupClient();
provider.setupCerts();

describe(`BASIC ${route} with session`, function() {
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

describe(`BASIC ${route} without session`, function() {

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

describe(`BASIC ${route} interactions required`, function() {
  it('no account id was found in the session info');
  it('login was requested by the client by prompt parameter');
  it('session is too old for this authentication request');
  it('session subject value differs from the one requested');
  it('none of multiple authentication context class references requested are met');
  it('single requested authentication context class reference is not met');
});

describe(`BASIC ${route} errors`, function() {

  agent.logout();

  it('dupe parameters', function() {
    // fake a query like this scope=openid&scope=openid
    let spy = sinon.spy();
    provider.once('authentication.error', spy);
    const auth = new AuthenticationRequest({
      response_type: 'code',
      scope: ['openid', 'openid']
    });

    return agent.get(route)
      .query(auth)
      .expect(302)
      .expect(function() {
        expect(spy.called).to.be.true;
      })
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('invalid_request'))
      .expect(auth.validateErrorDescription('parameters must not be provided twice. scope'));
  });

  it('disallowed response mode', function() {
    let spy = sinon.spy();
    provider.once('authentication.error', spy);
    const auth = new AuthenticationRequest({
      response_type: 'code token',
      scope: 'openid',
      response_mode: 'query'
    });

    return agent.get(route)
      .query(auth)
      .expect(302)
      .expect(function() {
        expect(spy.called).to.be.true;
      })
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('invalid_request'))
      .expect(auth.validateErrorDescription('response_mode not allowed for this response_type'));
  });

  ['request', 'request_uri', 'registration'].forEach(function(param) {
    it(`not supported parameter ${param}`, function() {
      let spy = sinon.spy();
      provider.once('authentication.error', spy);
      const auth = new AuthenticationRequest({
        response_type: 'code',
        scope: 'openid',
        [param]: 'some'
      });

      return agent.get(route)
        .query(auth)
        .expect(302)
        .expect(function() {
          expect(spy.called).to.be.true;
        })
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError(`${param}_not_supported`));
    });
  });

  it('missing mandatory parameter redirect_uri');

  ['response_type', 'client_id', 'scope'].forEach(function(param) {
    it(`missing mandatory parameter ${param}`, function() {
      let spy = sinon.spy();
      provider.once('authentication.error', spy);
      const auth = new AuthenticationRequest({
        response_type: 'code',
        scope: 'openid'
      });
      delete auth[param];

      return agent.get(route)
        .query(auth)
        .expect(302)
        .expect(function() {
          expect(spy.called).to.be.true;
        })
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_request'))
        .expect(auth.validateErrorDescription(`missing required parameter(s) ${param}`));
    });
  });

  it('unsupported prompt', function() {
    let spy = sinon.spy();
    provider.once('authentication.error', spy);
    const auth = new AuthenticationRequest({
      response_type: 'code',
      scope: 'openid',
      prompt: 'unsupported'
    });

    return agent.get(route)
      .query(auth)
      .expect(302)
      .expect(function() {
        expect(spy.called).to.be.true;
      })
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('invalid_request'))
      .expect(auth.validateErrorDescription('invalid prompt value(s) provided. (unsupported)'));
  });

  it('bad prompt combination', function() {
    let spy = sinon.spy();
    provider.once('authentication.error', spy);
    const auth = new AuthenticationRequest({
      response_type: 'code',
      scope: 'openid',
      prompt: 'none login'
    });

    return agent.get(route)
      .query(auth)
      .expect(302)
      .expect(function() {
        expect(spy.called).to.be.true;
      })
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('invalid_request'))
      .expect(auth.validateErrorDescription('prompt none must only be used alone'));
  });

  it('unsupported scope', function() {
    let spy = sinon.spy();
    provider.once('authentication.error', spy);
    const auth = new AuthenticationRequest({
      response_type: 'code',
      scope: 'openid and unsupported'
    });

    return agent.get(route)
      .query(auth)
      .expect(302)
      .expect(function() {
        expect(spy.called).to.be.true;
      })
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('invalid_request'))
      .expect(auth.validateErrorDescription('invalid scope value(s) provided. (and,unsupported)'));
  });

  it('missing openid scope', function() {
    let spy = sinon.spy();
    provider.once('authentication.error', spy);
    const auth = new AuthenticationRequest({
      response_type: 'code',
      scope: 'profile'
    });

    return agent.get(route)
      .query(auth)
      .expect(302)
      .expect(function() {
        expect(spy.called).to.be.true;
      })
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('invalid_request'))
      .expect(auth.validateErrorDescription('openid is required scope'));
  });

  it('invalid use of scope offline_access', function() {
    let spy = sinon.spy();
    provider.once('authentication.error', spy);
    const auth = new AuthenticationRequest({
      response_type: 'code',
      scope: 'openid offline_access'
    });

    return agent.get(route)
      .query(auth)
      .expect(302)
      .expect(function() {
        expect(spy.called).to.be.true;
      })
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('invalid_request'))
      .expect(auth.validateErrorDescription('offline_access scope requires consent prompt'));
  });

  it('unrecognized client_id provided', function() {
    let spy = sinon.spy();
    provider.once('authentication.error', spy);
    const auth = new AuthenticationRequest({
      response_type: 'code',
      scope: 'openid',
      client_id: 'unrecognized'
    });

    return agent.get(route)
      .query(auth)
      .expect(302)
      .expect(function() {
        expect(spy.called).to.be.true;
      })
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('invalid_request'))
      .expect(auth.validateErrorDescription('unrecognized client_id'));
  });

  it('unsupported response_type', function() {
    let spy = sinon.spy();
    provider.once('authentication.error', spy);
    const auth = new AuthenticationRequest({
      response_type: 'unsupported',
      scope: 'openid'
    });

    return agent.get(route)
      .query(auth)
      .expect(302)
      .expect(function() {
        expect(spy.called).to.be.true;
      })
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('unsupported_response_type'))
      .expect(auth.validateErrorDescription('response_type not supported. (unsupported)'));
  });

  it('restricted response_type', function() {
    let spy = sinon.spy();
    provider.once('authentication.error', spy);
    const auth = new AuthenticationRequest({
      response_type: 'none',
      scope: 'openid'
    });

    return agent.get(route)
      .query(auth)
      .expect(302)
      .expect(function() {
        expect(spy.called).to.be.true;
      })
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('restricted_response_type'))
      .expect(auth.validateErrorDescription('response_type not allowed for this client'));
  });

  it('redirect_uri mismatch');

  describe('login state specific', function() {
    agent.login();

    it('malformed id_token_hint', function() {
      let spy = sinon.spy();
      provider.once('authentication.error', spy);
      const auth = new AuthenticationRequest({
        response_type: 'code',
        scope: 'openid',
        id_token_hint: 'invalid'
      });

      return agent.get(route)
      .query(auth)
      .expect(302)
      .expect(function() {
        expect(spy.called).to.be.true;
      })
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('invalid_request'))
      .expect(auth.validateErrorDescription('could not validate id_token_hint'));
    });
  });
});
