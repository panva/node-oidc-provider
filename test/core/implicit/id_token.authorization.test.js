'use strict';

const bootstrap = require('../../test_helper');
const sinon = require('sinon');
const { expect } = require('chai');

const route = '/auth';

describe('IMPLICIT id_token', () => {
  const { provider, agent, AuthorizationRequest, wrap } = bootstrap(__dirname);
  provider.setupClient();

  ['get', 'post'].forEach((verb) => {
    describe(`IMPLICIT id_token ${verb} ${route} with session`, () => {
      before(agent.login);

      it('responds with a id_token in fragment', () => {
        const auth = new AuthorizationRequest({
          response_type: 'id_token',
          scope: 'openid'
        });

        return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['id_token', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation);
      });
    });

    describe(`IMPLICIT id_token ${verb} ${route} errors`, () => {
  // before(agent.logout);

      it('disallowed response mode', () => {
        const spy = sinon.spy();
        provider.once('authorization.error', spy);
        const auth = new AuthorizationRequest({
          response_type: 'code id_token',
          scope: 'openid',
          response_mode: 'query'
        });

        return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
      })
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('invalid_request'))
      .expect(auth.validateErrorDescription('response_mode not allowed for this response_type'));
      });

      it('missing mandatory parameter nonce', () => {
        const spy = sinon.spy();
        provider.once('authorization.error', spy);
        const auth = new AuthorizationRequest({
          response_type: 'id_token',
          scope: 'openid'
        });
        delete auth.nonce;

        return agent.get(route)
      .query(auth)
      .expect(302)
      .expect(() => {
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
