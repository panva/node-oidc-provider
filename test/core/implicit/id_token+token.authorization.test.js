'use strict';

const bootstrap = require('../../test_helper');
const sinon = require('sinon');
const { expect } = require('chai');

const route = '/auth';

describe('IMPLICIT id_token+token', function () {
  const { provider, agent, AuthorizationRequest, wrap } = bootstrap(__dirname);
  provider.setupClient();
  provider.setupCerts();

  ['get', 'post'].forEach((verb) => {
    describe(`${verb} ${route} with session`, function () {
      before(agent.login);

      it('responds with a id_token in fragment', function () {
        const auth = new AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid'
        });

        return wrap({ agent, route, verb, auth })
        .expect(302)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['id_token', 'state', 'access_token', 'expires_in', 'token_type']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation);
      });
    });

    describe(`${verb} ${route} errors`, function () {
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

      it('missing mandatory parameter nonce', function () {
        const spy = sinon.spy();
        provider.once('authorization.error', spy);
        const auth = new AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid'
        });
        delete auth.nonce;

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
        .expect(auth.validateErrorDescription('missing required parameter(s) nonce'));
      });
    });
  });
});
