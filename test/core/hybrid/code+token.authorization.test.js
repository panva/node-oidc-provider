'use strict';

const bootstrap = require('../../test_helper');
const sinon = require('sinon');
const { expect } = require('chai');

const route = '/auth';

describe('HYBRID code+token', function () {
  before(bootstrap(__dirname)); // provider, agent, AuthorizationRequest, wrap

  ['get', 'post'].forEach((verb) => {
    describe(`${verb} ${route} with session`, function () {
      before(function () { return this.login(); });

      it('responds with a access_token and code in fragment', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code token',
          scope: 'openid'
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['code', 'state', 'access_token', 'expires_in', 'token_type']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);
      });

      it('ignores the scope offline_access unless prompt consent is present', function () {
        const spy = sinon.spy();
        this.provider.once('token.issued', spy);

        const auth = new this.AuthorizationRequest({
          response_type: 'code token',
          scope: 'openid offline_access'
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validateClientLocation)
          .expect(() => {
            expect(spy.firstCall.args[0]).to.have.property('scope').and.not.include('offline_access');
          });
      });
    });

    describe(`${verb} ${route} errors`, function () {
      it('disallowed response mode', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          response_type: 'code token',
          scope: 'openid',
          response_mode: 'query'
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
    });
  });
});
