'use strict';

const {
  provider, agent, AuthenticationRequest
} = require('../../test_helper')(__dirname);
const sinon = require('sinon');
const { expect } = require('chai');

const route = '/auth';

provider.setupClient();
provider.setupCerts();

function getSession(agent) {
  let { value: sessionId } = agent.jar.getCookie('_session', { path: '/' });
  let key = provider.Session.adapter.key(sessionId);
  return provider.Session.adapter.storage.get(key);
}

function wrap(opts) {
  let { agent, route, verb, auth } = opts;
  switch (verb) {
    case 'get':
      return agent
        .get(route)
        .query(auth);
    case 'post':
      return agent
        .post(route)
        .send(auth)
        .set('Content-Type', 'application/x-www-form-urlencoded');
  }
}

['get', 'post'].forEach((verb) => {

describe(`BASIC ${verb} ${route} with session`, function() {
  before(agent.login);

  it('responds with a code in search', function() {
    const auth = new AuthenticationRequest({
      response_type: 'code',
      scope: 'openid'
    });

    return wrap({ agent, route, verb, auth })
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

    return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['code', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation);
  });
});

describe(`BASIC ${verb} ${route} interactions`, function() {

  beforeEach(agent.login);
  after(agent.logout);

  it('no account id was found in the session info', function() {
    const session = getSession(agent);
    delete session.loginTs;
    delete session.account;

    const auth = new AuthenticationRequest({
      response_type: 'code',
      scope: 'openid'
    });

    return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(auth.validateInteractionRedirect)
      .expect(auth.validateInteractionError('login_required', 'no_session'));
  });

  describe('requested by the End-User', function() {
    it('login was requested by the client by prompt parameter', function() {
      const auth = new AuthenticationRequest({
        response_type: 'code',
        prompt: 'login',
        scope: 'openid'
      });

      return wrap({ agent, route, verb, auth })
        .expect(302)
        .expect(auth.validateInteractionRedirect)
        .expect(auth.validateInteractionError('login_required', 'login_prompt'));
    });

    it('session is too old for this authentication request', function() {
      const session = getSession(agent);
      session.loginTs = (new Date() / 1000 | 0) - 3600; // an hour ago

      const auth = new AuthenticationRequest({
        response_type: 'code',
        max_age: '1800', // 30 minutes old session max
        scope: 'openid'
      });

      return wrap({ agent, route, verb, auth })
        .expect(302)
        .expect(auth.validateInteractionRedirect)
        .expect(auth.validateInteractionError('login_required', 'max_age'));
    });

    it('//claims tests; session subject value differs from the one requested');
    it('//claims tests; none of multiple authentication context class references requested are met');
    it('//claims tests; single requested authentication context class reference is not met');
  });

});

describe(`BASIC ${verb} ${route} errors`, function() {

  // before(agent.logout);

  it('dupe parameters', function() {
    // fake a query like this scope=openid&scope=openid
    let spy = sinon.spy();
    provider.once('authentication.error', spy);
    const auth = new AuthenticationRequest({
      response_type: 'code',
      scope: ['openid', 'openid']
    });

    return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(function() {
        expect(spy.calledOnce).to.be.true;
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

    return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(function() {
        expect(spy.calledOnce).to.be.true;
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
          expect(spy.calledOnce).to.be.true;
        })
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError(`${param}_not_supported`));
    });
  });

  it('missing mandatory parameter redirect_uri', function() {
    let emitSpy = sinon.spy();
    let renderSpy = sinon.spy(provider.configuration, 'renderError');
    provider.once('authentication.error', emitSpy);
    const auth = new AuthenticationRequest({
      response_type: 'code',
      scope: 'openid'
    });
    delete auth.redirect_uri;

    return agent.get(route)
      .query(auth)
      .expect(function() {
        renderSpy.restore();
      })
      .expect(200)
      .expect(function() {
        expect(emitSpy.calledOnce).to.be.true;
        expect(renderSpy.calledOnce).to.be.true;
        let renderArgs = renderSpy.args[0][0];
        expect(renderArgs).to.have.property('error', 'invalid_request');
        expect(renderArgs).to.have.property('error_description', 'missing required parameter(s) redirect_uri');

      });
  });

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
          expect(spy.calledOnce).to.be.true;
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

    return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(function() {
        expect(spy.calledOnce).to.be.true;
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

    return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(function() {
        expect(spy.calledOnce).to.be.true;
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

    return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(function() {
        expect(spy.calledOnce).to.be.true;
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

    return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(function() {
        expect(spy.calledOnce).to.be.true;
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

    return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(function() {
        expect(spy.calledOnce).to.be.true;
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

    return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(function() {
        expect(spy.calledOnce).to.be.true;
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

    return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(function() {
        expect(spy.calledOnce).to.be.true;
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

    return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(function() {
        expect(spy.calledOnce).to.be.true;
      })
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('restricted_response_type'))
      .expect(auth.validateErrorDescription('response_type not allowed for this client'));
  });

  it('redirect_uri mismatch', function() {
    let emitSpy = sinon.spy();
    let renderSpy = sinon.spy(provider.configuration, 'renderError');
    provider.once('authentication.error', emitSpy);
    const auth = new AuthenticationRequest({
      response_type: 'code',
      scope: 'openid',
      redirect_uri: 'http://example.client.dev/notregistered'
    });

    return agent.get(route)
      .query(auth)
      .expect(function() {
        renderSpy.restore();
      })
      .expect(200)
      .expect(function() {
        expect(emitSpy.calledOnce).to.be.true;
        expect(renderSpy.calledOnce).to.be.true;
        let renderArgs = renderSpy.args[0][0];
        expect(renderArgs).to.have.property('error', 'redirect_uri_mismatch');
        expect(renderArgs).to.have.property('error_description', 'redirect_uri did not match any client\'s registered redirect_uri');

      });
  });

  describe('login state specific', function() {
    before(agent.login);

    it('malformed id_token_hint', function() {
      let spy = sinon.spy();
      provider.once('authentication.error', spy);
      const auth = new AuthenticationRequest({
        response_type: 'code',
        scope: 'openid',
        id_token_hint: 'invalid'
      });

      return wrap({ agent, route, verb, auth })
        .expect(302)
        .expect(function() {
          expect(spy.calledOnce).to.be.true;
        })
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_request'))
        .expect(auth.validateErrorDescription('could not validate id_token_hint'));
    });
  });
});
});
