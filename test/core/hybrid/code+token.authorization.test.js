'use strict';

const {
  provider, agent, AuthorizationRequest, getSession, wrap
} = require('../../test_helper')(__dirname);
const sinon = require('sinon');
const { expect } = require('chai');

const route = '/auth';

provider.setupClient();
provider.setupCerts();

['get', 'post'].forEach((verb) => {
  describe(`HYBRID code+token ${verb} ${route} with session`, function () {
    before(agent.login);

    it('responds with a access_token and code in fragment', function () {
      const auth = new AuthorizationRequest({
        response_type: 'code token',
        scope: 'openid'
      });

      return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['code', 'state', 'access_token', 'expires_in', 'token_type']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation);
    });
  });

  describe(`HYBRID code+token ${verb} ${route} interactions`, function () {
    beforeEach(agent.login);
    after(agent.logout);

    it('no account id was found in the session info', function () {
      const session = getSession(agent);
      delete session.loginTs;
      delete session.account;

      const auth = new AuthorizationRequest({
        response_type: 'code token',
        scope: 'openid'
      });

      return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(auth.validateInteractionRedirect)
      .expect(auth.validateInteractionError('login_required', 'no_session'));
    });

    describe('requested by the End-User', function () {
      it('login was requested by the client by prompt parameter', function () {
        const auth = new AuthorizationRequest({
          response_type: 'code token',
          prompt: 'login',
          scope: 'openid'
        });

        return wrap({ agent, route, verb, auth })
        .expect(302)
        .expect(auth.validateInteractionRedirect)
        .expect(auth.validateInteractionError('login_required', 'login_prompt'));
      });

      it('session is too old for this authorization request', function () {
        const session = getSession(agent);
        session.loginTs = (new Date() / 1000 | 0) - 3600; // an hour ago

        const auth = new AuthorizationRequest({
          response_type: 'code token',
          max_age: '1800', // 30 minutes old session max
          scope: 'openid'
        });

        return wrap({ agent, route, verb, auth })
        .expect(302)
        .expect(auth.validateInteractionRedirect)
        .expect(auth.validateInteractionError('login_required', 'max_age'));
      });
    });
  });

  describe(`HYBRID code+token ${verb} ${route} errors`, function () {
    it('dupe parameters', function () {
      const spy = sinon.spy();
      provider.once('authorization.error', spy);
      // fake a query like this scope=openid&scope=openid
      const auth = new AuthorizationRequest({
        response_type: 'code token',
        scope: ['openid', 'openid']
      });

      return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(function () {
        expect(spy.calledOnce).to.be.true;
      })
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('invalid_request'))
      .expect(auth.validateErrorDescription('parameters must not be provided twice. scope'));
    });

    it('disallowed response mode', function () {
      const spy = sinon.spy();
      provider.once('authorization.error', spy);
      const auth = new AuthorizationRequest({
        response_type: 'code token',
        scope: 'openid',
        response_mode: 'query'
      });

      return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(function () {
        expect(spy.calledOnce).to.be.true;
      })
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('invalid_request'))
      .expect(auth.validateErrorDescription('response_mode not allowed for this response_type'));
    });

    ['request', 'request_uri', 'registration'].forEach(function (param) {
      it(`not supported parameter ${param}`, function () {
        const spy = sinon.spy();
        provider.once('authorization.error', spy);
        const auth = new AuthorizationRequest({
          response_type: 'code token',
          scope: 'openid',
          [param]: 'some'
        });

        return agent.get(route)
        .query(auth)
        .expect(302)
        .expect(function () {
          expect(spy.calledOnce).to.be.true;
        })
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError(`${param}_not_supported`));
      });
    });

    context('when client has more then one redirect_uri', function () {
      before(function * () {
        (yield provider.get('Client').find('client')).redirectUris.push('https://someOtherUri.com');
      });

      after(function * () {
        (yield provider.get('Client').find('client')).redirectUris.pop();
      });

      it('missing mandatory parameter redirect_uri', function () {
        const emitSpy = sinon.spy();
        const renderSpy = sinon.spy(provider.configuration(), 'renderError');
        provider.once('authorization.error', emitSpy);
        const auth = new AuthorizationRequest({
          response_type: 'code token',
          scope: 'openid'
        });
        delete auth.redirect_uri;

        return agent.get(route)
        .query(auth)
        .expect(function () {
          renderSpy.restore();
        })
        .expect(400)
        .expect(function () {
          expect(emitSpy.calledOnce).to.be.true;
          expect(renderSpy.calledOnce).to.be.true;
          const renderArgs = renderSpy.args[0][1];
          expect(renderArgs).to.have.property('error', 'invalid_request');
          expect(renderArgs).to.have.property('error_description', 'missing required parameter(s) redirect_uri');
        });
      });
    });

    ['client_id', 'scope'].forEach(function (param) {
      it(`missing mandatory parameter ${param}`, function () {
        const spy = sinon.spy();
        provider.once('authorization.error', spy);
        const auth = new AuthorizationRequest({
          response_type: 'code token',
          scope: 'openid'
        });
        delete auth[param];

        return agent.get(route)
        .query(auth)
        .expect(302)
        .expect(function () {
          expect(spy.calledOnce).to.be.true;
        })
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_request'))
        .expect(auth.validateErrorDescription(`missing required parameter(s) ${param}`));
      });
    });

    it('missing mandatory parameter response_type', function () {
      const spy = sinon.spy();
      provider.once('authorization.error', spy);
      const auth = new AuthorizationRequest({
        response_type: 'code token',
        scope: 'openid'
      });
      delete auth.response_type;

      return agent.get(route)
    .query(auth)
    .expect(302)
    .expect(function () {
      expect(spy.calledOnce).to.be.true;
    })
    .expect(auth.validatePresence(['error', 'error_description', 'state']))
    .expect(auth.validateState)
    .expect(auth.validateClientLocation)
    .expect(auth.validateError('invalid_request'))
    .expect(auth.validateErrorDescription('missing required parameter(s) response_type'));
    });

    it('unsupported prompt', function () {
      const spy = sinon.spy();
      provider.once('authorization.error', spy);
      const auth = new AuthorizationRequest({
        response_type: 'code token',
        scope: 'openid',
        prompt: 'unsupported'
      });

      return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(function () {
        expect(spy.calledOnce).to.be.true;
      })
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('invalid_request'))
      .expect(auth.validateErrorDescription('invalid prompt value(s) provided. (unsupported)'));
    });

    it('bad prompt combination', function () {
      const spy = sinon.spy();
      provider.once('authorization.error', spy);
      const auth = new AuthorizationRequest({
        response_type: 'code token',
        scope: 'openid',
        prompt: 'none login'
      });

      return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(function () {
        expect(spy.calledOnce).to.be.true;
      })
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('invalid_request'))
      .expect(auth.validateErrorDescription('prompt none must only be used alone'));
    });

    it('unsupported scope', function () {
      const spy = sinon.spy();
      provider.once('authorization.error', spy);
      const auth = new AuthorizationRequest({
        response_type: 'code token',
        scope: 'openid and unsupported'
      });

      return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(function () {
        expect(spy.calledOnce).to.be.true;
      })
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('invalid_request'))
      .expect(auth.validateErrorDescription('invalid scope value(s) provided. (and,unsupported)'));
    });

    it('missing openid scope', function () {
      const spy = sinon.spy();
      provider.once('authorization.error', spy);
      const auth = new AuthorizationRequest({
        response_type: 'code token',
        scope: 'profile'
      });

      return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(function () {
        expect(spy.calledOnce).to.be.true;
      })
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('invalid_request'))
      .expect(auth.validateErrorDescription('openid is required scope'));
    });

    it('invalid use of scope offline_access', function () {
      const spy = sinon.spy();
      provider.once('authorization.error', spy);
      const auth = new AuthorizationRequest({
        response_type: 'code token',
        scope: 'openid offline_access'
      });

      return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(function () {
        expect(spy.calledOnce).to.be.true;
      })
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('invalid_request'))
      .expect(auth.validateErrorDescription('offline_access scope requires consent prompt'));
    });

    it('unrecognized client_id provided', function () {
      const spy = sinon.spy();
      provider.once('authorization.error', spy);
      const auth = new AuthorizationRequest({
        response_type: 'code token',
        scope: 'openid',
        client_id: 'unrecognized'
      });

      return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(function () {
        expect(spy.calledOnce).to.be.true;
      })
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('invalid_request'))
      .expect(auth.validateErrorDescription('unrecognized client_id'));
    });

    it('unsupported response_type', function () {
      const spy = sinon.spy();
      provider.once('authorization.error', spy);
      const auth = new AuthorizationRequest({
        response_type: 'unsupported',
        scope: 'openid'
      });

      return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(function () {
        expect(spy.calledOnce).to.be.true;
      })
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('unsupported_response_type'))
      .expect(auth.validateErrorDescription('response_type not supported. (unsupported)'));
    });

    it('restricted response_type', function () {
      const spy = sinon.spy();
      provider.once('authorization.error', spy);
      const auth = new AuthorizationRequest({
        response_type: 'code',
        scope: 'openid'
      });

      return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(function () {
        expect(spy.calledOnce).to.be.true;
      })
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('restricted_response_type'))
      .expect(auth.validateErrorDescription('response_type not allowed for this client'));
    });

    it('redirect_uri mismatch', function () {
      const emitSpy = sinon.spy();
      const renderSpy = sinon.spy(provider.configuration(), 'renderError');
      provider.once('authorization.error', emitSpy);
      const auth = new AuthorizationRequest({
        response_type: 'code token',
        scope: 'openid',
        redirect_uri: 'http://example.client.dev/notregistered'
      });

      return agent.get(route)
      .query(auth)
      .expect(function () {
        renderSpy.restore();
      })
      .expect(400)
      .expect(function () {
        expect(emitSpy.calledOnce).to.be.true;
        expect(renderSpy.calledOnce).to.be.true;
        const renderArgs = renderSpy.args[0][1];
        expect(renderArgs).to.have.property('error', 'redirect_uri_mismatch');
        expect(renderArgs).to.have.property('error_description', 'redirect_uri did not match any client\'s registered redirect_uri');
      });
    });

    describe('login state specific', function () {
      before(agent.login);

      it('malformed id_token_hint', function () {
        const spy = sinon.spy();
        provider.once('authorization.error', spy);
        const auth = new AuthorizationRequest({
          response_type: 'code token',
          scope: 'openid',
          id_token_hint: 'invalid'
        });

        return wrap({ agent, route, verb, auth })
        .expect(302)
        .expect(function () {
          expect(spy.calledOnce).to.be.true;
        })
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_request'))
        .expect(auth.validateErrorDescription('could not validate id_token_hint'));
      });
    });
  });
});
