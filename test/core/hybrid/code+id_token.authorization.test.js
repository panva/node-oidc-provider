const sinon = require('sinon');
const { expect } = require('chai');

const bootstrap = require('../../test_helper');

const route = '/auth';
const response_type = 'code id_token';
const scope = 'openid';

describe('HYBRID code+id_token', () => {
  before(bootstrap(__dirname));

  ['get', 'post'].forEach((verb) => {
    describe(`${verb} ${route} with session`, () => {
      before(function () { return this.login(); });

      it('responds with a id_token and code in fragment', function () {
        const auth = new this.AuthorizationRequest({
          response_type,
          scope,
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['code', 'id_token', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);
      });

      it('handles mixed up response_type order', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'id_token code',
          scope,
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['code', 'id_token', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);
      });

      it('populates ctx.oidc.entities', function (done) {
        this.provider.use(this.assertOnce((ctx) => {
          expect(ctx.oidc.entities).to.have.keys('Client', 'Account', 'AuthorizationCode', 'Session');
        }, done));

        const auth = new this.AuthorizationRequest({
          response_type,
          scope,
        });

        this.wrap({ route, verb, auth }).end(() => {});
      });

      describe('ignoring the offline_access scope', () => {
        bootstrap.skipConsent();

        it('ignores the scope offline_access unless prompt consent is present', function () {
          const spy = sinon.spy();
          this.provider.once('authorization_code.saved', spy);

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
            });
        });

        it('ignores the scope offline_access unless the client can do refresh_token exchange', function () {
          const spy = sinon.spy();
          this.provider.once('authorization_code.saved', spy);

          const auth = new this.AuthorizationRequest({
            client_id: 'client-no-refresh',
            response_type,
            scope: 'openid offline_access',
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

      it('missing mandatory parameter nonce', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          response_type,
          scope,
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
          .expect(auth.validateErrorDescription("missing required parameter 'nonce'"));
      });
    });
  });
});
