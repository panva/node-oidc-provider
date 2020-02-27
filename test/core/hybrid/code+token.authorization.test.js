const sinon = require('sinon');
const { expect } = require('chai');

const bootstrap = require('../../test_helper');

const route = '/auth';
const response_type = 'code token';
const scope = 'openid';

describe('HYBRID code+token', () => {
  before(bootstrap(__dirname));

  ['get', 'post'].forEach((verb) => {
    describe(`${verb} ${route} with session`, () => {
      before(function () { return this.login(); });

      it('responds with a access_token and code in fragment', function () {
        const auth = new this.AuthorizationRequest({
          response_type,
          scope,
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['code', 'state', 'access_token', 'expires_in', 'token_type', 'scope']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);
      });

      it('handles mixed up response_type order', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'token code',
          scope,
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['code', 'state', 'access_token', 'expires_in', 'token_type', 'scope']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);
      });

      it('populates ctx.oidc.entities', function (done) {
        this.provider.use(this.assertOnce((ctx) => {
          expect(ctx.oidc.entities).to.have.keys('Client', 'Account', 'AuthorizationCode', 'AccessToken', 'Session');
        }, done));

        const auth = new this.AuthorizationRequest({
          response_type,
          scope,
        });

        this.wrap({ route, verb, auth }).end(() => {});
      });

      it('ignores the scope offline_access unless prompt consent is present', function () {
        const spy = sinon.spy();
        this.provider.once('authorization_code.saved', spy);
        this.provider.once('access_token.saved', spy);

        const auth = new this.AuthorizationRequest({
          response_type,
          scope: 'openid offline_access',
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validateClientLocation)
          .expect(() => {
            expect(spy.firstCall.args[0]).to.have.property('scope').and.not.include('offline_access');
            expect(spy.secondCall.args[0]).to.have.property('scope').and.not.include('offline_access');
          });
      });
    });

    describe(`${verb} ${route} with the scope not being fulfilled`, () => {
      before(function () {
        return this.login({
          scope: 'openid profile email',
          rejectedScopes: ['email'],
        });
      });

      it('responds with an extra parameter scope', async function () {
        const auth = new this.AuthorizationRequest({
          response_type,
          scope: 'openid profile email',
        });

        await this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['code', 'state', 'access_token', 'expires_in', 'token_type', 'scope']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateResponseParameter('scope', 'openid profile'));
      });
    });

    describe(`${verb} ${route} errors`, () => {
      it('disallowed response mode', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          response_type,
          scope,
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
    });
  });
});
