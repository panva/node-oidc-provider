const bootstrap = require('../../test_helper');
const sinon = require('sinon');
const { expect } = require('chai');

const route = '/auth';

describe('IMPLICIT id_token', () => {
  before(bootstrap(__dirname)); // provider, agent, AuthorizationRequest, wrap

  ['get', 'post'].forEach((verb) => {
    describe(`IMPLICIT id_token ${verb} ${route} with session`, () => {
      before(function () { return this.login(); });

      it('responds with a id_token in fragment', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'id_token',
          scope: 'openid',
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);
      });

      it('ignores offline_access scope for non code-including response_types', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'id_token',
          scope: 'openid offline_access',
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);
      });
    });

    describe(`IMPLICIT id_token ${verb} ${route} errors`, () => {
      it('disallowed response mode', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          response_type: 'code id_token',
          scope: 'openid',
          response_mode: 'query',
        });

        return this.wrap({ route, verb, auth })
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

      it('missing mandatory parameter nonce', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          response_type: 'id_token',
          scope: 'openid',
        });
        delete auth.nonce;

        return this.agent.get(route)
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
