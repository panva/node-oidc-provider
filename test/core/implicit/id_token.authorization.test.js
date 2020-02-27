const querystring = require('querystring');
const url = require('url');

const sinon = require('sinon');
const { expect } = require('chai');

const bootstrap = require('../../test_helper');

const route = '/auth';
const response_type = 'id_token';
const scope = 'openid';

describe('IMPLICIT id_token', () => {
  before(bootstrap(__dirname));

  ['get', 'post'].forEach((verb) => {
    describe(`IMPLICIT id_token ${verb} ${route} with session`, () => {
      before(function () { return this.login(); });

      it('responds with a id_token in fragment', function () {
        const auth = new this.AuthorizationRequest({
          response_type,
          scope,
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);
      });

      it('populates ctx.oidc.entities', function (done) {
        this.provider.use(this.assertOnce((ctx) => {
          expect(ctx.oidc.entities).to.have.keys('Client', 'Account', 'Session');
        }, done));

        const auth = new this.AuthorizationRequest({
          response_type,
          scope,
        });

        this.wrap({ route, verb, auth }).end(() => {});
      });

      it('ignores offline_access scope for non code-including response_types', function () {
        const auth = new this.AuthorizationRequest({
          response_type,
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
      before(function () { return this.login(); });

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
          // .expect(auth.validateFragment) // response mode will be honoured for error response
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('response_mode not allowed for this response_type'));
      });

      it('HMAC ID Token Hint with expired secret errors', async function () {
        const client = await this.provider.Client.find('client-expired-secret');
        client.clientSecretExpiresAt = 0;

        let auth = new this.AuthorizationRequest({
          client_id: 'client-expired-secret',
          response_type,
          scope,
        });

        let idTokenHint;
        await this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token', 'state']))
          .expect((response) => {
            const { query } = url.parse(response.headers.location.replace('#', '?'), true);
            idTokenHint = query.id_token;
          });

        client.clientSecretExpiresAt = 1;

        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        auth = new this.AuthorizationRequest({
          client_id: 'client-expired-secret',
          response_type,
          id_token_hint: idTokenHint,
          scope,
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
          })
          .expect(auth.validateFragment) // response mode will be honoured for error response
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_client'))
          .expect(auth.validateErrorDescription('client secret is expired - cannot validate ID Token Hint'));
      });

      it('HMAC ID Token with expired secret errors', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          client_id: 'client-expired-secret',
          response_type,
          scope,
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
          })
          .expect(auth.validateFragment) // response mode will be honoured for error response
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_client'))
          .expect(auth.validateErrorDescription('client secret is expired - cannot issue an ID Token (HS256)'));
      });

      it('response mode provided twice', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          response_type,
          scope,
          response_mode: 'fragment',
        });

        const wrapped = ((data) => { // eslint-disable-line consistent-return
          switch (verb) {
            case 'get':
              return this.agent
                .get(route)
                .query(`${data}&response_mode=fragment`);
            case 'post':
              return this.agent
                .post(route)
                .send(`${data}&response_mode=fragment`)
                .type('form');
            default:
          }
        })(querystring.stringify(auth));

        return wrapped.expect(302)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
          })
          .expect(auth.validateFragment) // mode will still be figured out from the response_type
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription("'response_mode' parameter must not be provided twice"));
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
