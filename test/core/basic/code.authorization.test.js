const querystring = require('querystring');

const sinon = require('sinon');
const { expect } = require('chai');

const bootstrap = require('../../test_helper');
const epochTime = require('../../../lib/helpers/epoch_time');
const {
  InvalidRequest,
  InvalidClient,
  RedirectUriMismatch,
} = require('../../../lib/helpers/errors');

const route = '/auth';
const response_type = 'code';
const scope = 'openid';

describe('BASIC code', () => {
  before(bootstrap(__dirname));

  ['get', 'post'].forEach((verb) => {
    describe(`${verb} ${route} with session`, () => {
      before(function () { return this.login(); });

      it('responds with a code in search', function () {
        const auth = new this.AuthorizationRequest({
          response_type,
          scope,
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validatePresence(['code', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);
      });

      it('responds with a code in fragment', function () {
        const auth = new this.AuthorizationRequest({
          response_type,
          response_mode: 'fragment',
          scope,
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['code', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);
      });

      it('populates ctx.oidc.entities', function (done) {
        this.provider.use(this.assertOnce((ctx) => {
          expect(ctx.oidc.entities).to.have.keys('AuthorizationCode', 'Client', 'Account', 'Session');
        }, done));

        const auth = new this.AuthorizationRequest({
          response_type,
          scope,
        });

        this.wrap({ route, verb, auth }).end(() => {});
      });

      it('allows native apps to do none auth check when already authorized', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'none',
          prompt: 'none',
          client_id: 'client-native',
          redirect_uri: 'com.example.app:/cb',
          scope,
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validatePresence(['state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);
      });

      it('ignores unsupported scopes', function () {
        const spy = sinon.spy();
        this.provider.once('authorization_code.saved', spy);
        const auth = new this.AuthorizationRequest({
          response_type,
          scope: 'openid and unsupported',
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateClientLocation)
          .expect(() => {
            expect(spy.firstCall.args[0]).to.have.property('scope', 'openid');
          });
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
            prompt: 'consent',
            scope: 'openid offline_access',
          });

          return this.wrap({ route, verb, auth })
            .expect(302)
            .expect(auth.validateClientLocation)
            .expect(() => {
              expect(spy.firstCall.args[0]).to.have.property('scope').and.not.include('offline_access');
            });
        });
      });
    });

    describe(`${verb} ${route} interactions`, () => {
      before(function () { return this.logout(); });
      before(function () {
        this.policy = i(this.provider).configuration('interactions').policy;
        i(this.provider).configuration('interactions').policy = [];
      });

      after(function () {
        i(this.provider).configuration('interactions').policy = this.policy;
      });

      it('no account id was resolved and no interactions requested', async function () {
        const spy = sinon.spy();
        this.provider.on('authorization.error', spy);

        const auth = new this.AuthorizationRequest({
          response_type,
          scope,
        });

        await this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateClientLocation)
          .expect(auth.validatePresence(['error', 'state']))
          .expect(auth.validateError('access_denied'));

        expect(spy.calledOnce).to.be.true;
        expect(spy.args[0][1]).to.have.property('error_detail', 'authorization request resolved without requesting interactions but no account id was resolved');
      });

      it('no scope was resolved and no interactions requested', async function () {
        await this.login();
        const spy = sinon.spy();
        this.provider.on('authorization.error', spy);

        const auth = new this.AuthorizationRequest({
          response_type,
          // scope,
        });

        await this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateClientLocation)
          .expect(auth.validatePresence(['error', 'state']))
          .expect(auth.validateError('access_denied'));

        expect(spy.calledOnce).to.be.true;
        expect(spy.args[0][1]).to.have.property('error_detail', 'authorization request resolved without requesting interactions but no scope was granted');
      });
    });

    describe(`${verb} ${route} interactions`, () => {
      beforeEach(function () { return this.login(); });
      after(function () { return this.logout(); });

      it('no account id was found in the session info', function () {
        const session = this.getSession();
        delete session.loginTs;
        delete session.account;

        const auth = new this.AuthorizationRequest({
          response_type,
          scope,
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateInteractionRedirect)
          .expect(auth.validateInteraction('login', 'no_session'));
      });

      it('client not authorized in session yet', function () {
        const session = this.getSession();
        session.authorizations = {};

        const auth = new this.AuthorizationRequest({
          response_type,
          scope,
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateInteractionRedirect)
          .expect(auth.validateInteraction('consent', 'client_not_authorized'));
      });

      it('additional scopes are requested', function () {
        const auth = new this.AuthorizationRequest({
          response_type,
          scope: 'openid email',
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateInteractionRedirect)
          .expect(auth.validateInteraction('consent', 'scopes_missing'));
      });

      it('are required for native clients by default', function () {
        const auth = new this.AuthorizationRequest({
          response_type,
          client_id: 'client-native',
          redirect_uri: 'com.example.app:/cb',
          scope,
          code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
          code_challenge_method: 'S256',
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateInteractionRedirect)
          .expect(auth.validateInteraction('consent', 'native_client_prompt'));
      });

      it('login was requested by the client by prompt parameter', function () {
        const auth = new this.AuthorizationRequest({
          response_type,
          prompt: 'login',
          scope,
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateInteractionRedirect)
          .expect(auth.validateInteraction('login', 'login_prompt'));
      });

      it('login was requested by the client by max_age=0', function () {
        const auth = new this.AuthorizationRequest({
          response_type,
          max_age: 0,
          scope,
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateInteractionRedirect)
          .expect(auth.validateInteraction('login', 'login_prompt'));
      });

      it('interaction check no session & max_age combo', function () {
        this.logout();

        const auth = new this.AuthorizationRequest({
          response_type,
          max_age: '1800', // 30 minutes old session max
          scope,
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateInteractionRedirect)
          .expect(auth.validateInteraction('login', 'max_age', 'no_session'));
      });

      it('session is too old for this authorization request (1/2)', function () {
        const session = this.getSession();
        session.loginTs = epochTime() - 3600; // an hour ago

        const auth = new this.AuthorizationRequest({
          response_type,
          max_age: '1800', // 30 minutes old session max
          scope,
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateInteractionRedirect)
          .expect(auth.validateInteraction('login', 'max_age'));
      });

      it('session is too old for this authorization request (2/2)', function () {
        const session = this.getSession();
        delete session.loginTs;

        const auth = new this.AuthorizationRequest({
          response_type,
          max_age: '1800', // 30 minutes old session max
          scope,
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateInteractionRedirect)
          .expect(auth.validateInteraction('login', 'max_age'));
      });

      it('custom interactions can be requested', function () {
        const auth = new this.AuthorizationRequest({
          response_type,
          scope,
          triggerCustomFail: 'foo',
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateInteractionRedirect)
          .expect(auth.validateInteraction('login', 'reason_foo'));
      });

      it('session is too old for this client', async function () {
        const client = await this.provider.Client.find('client');
        client.defaultMaxAge = 1800;

        const session = this.getSession();
        session.loginTs = epochTime() - 3600; // an hour ago

        const auth = new this.AuthorizationRequest({
          response_type,
          scope,
        });

        return this.wrap({ route, verb, auth })
          .expect(() => {
            delete client.defaultMaxAge;
          })
          .expect(302)
          .expect(auth.validateInteractionRedirect)
          .expect(auth.validateInteraction('login', 'max_age'));
      });
    });

    describe(`${verb} ${route} errors`, () => {
      it('dupe parameters are rejected and ignored in further processing', function () {
        // fake a query like this state=foo&state=foo
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          response_type,
          scope,
          state: 'foo',
        });

        const wrapped = ((data) => { // eslint-disable-line consistent-return
          switch (verb) {
            case 'get':
              return this.agent
                .get(route)
                .query(`${data}&state=foo&scope=openid&response_type=${response_type}`);
            case 'post':
              return this.agent
                .post(route)
                .send(`${data}&state=foo&scope=openid&response_type=${response_type}`)
                .type('form');
            default:
          }
        })(querystring.stringify(auth));

        return wrapped.expect(302)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
          })
          .expect(auth.validatePresence(['error', 'error_description'])) // notice state is not expected
          // .expect(auth.validateState) // notice state is not expected
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription("'response_type', 'scope', and 'state' parameters must not be provided twice"));
      });

      it('invalid response mode (not validated yet)', function () {
        // fake a query like this state=foo&state=foo to trigger
        // a validation error prior to validating response mode
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          response_type,
          scope,
          state: 'foo',
          response_mode: 'foo',
        });

        const wrapped = ((data) => { // eslint-disable-line consistent-return
          switch (verb) {
            case 'get':
              return this.agent
                .get(route)
                .query(`${data}&state=bar`);
            case 'post':
              return this.agent
                .post(route)
                .send(`${data}&state=bar`)
                .type('form');
            default:
          }
        })(querystring.stringify(auth));

        return wrapped.expect(302)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
          })
          .expect(auth.validatePresence(['error', 'error_description'])) // notice state is not expected
          // .expect(auth.validateState) // notice state is not expected
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription("'state' parameter must not be provided twice"));
      });

      it('response mode provided twice', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          response_type,
          scope,
          response_mode: 'query',
        });

        const wrapped = ((data) => { // eslint-disable-line consistent-return
          switch (verb) {
            case 'get':
              return this.agent
                .get(route)
                .query(`${data}&response_mode=query`);
            case 'post':
              return this.agent
                .post(route)
                .send(`${data}&response_mode=query`)
                .type('form');
            default:
          }
        })(querystring.stringify(auth));

        return wrapped.expect(302)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
          })
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription("'response_mode' parameter must not be provided twice"));
      });

      it('unregistered scope requested', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          client_id: 'client-limited-scope',
          response_type: 'code',
          scope: 'openid foobar offline_access', // foobar is ignored, offline_access is not whitelisted
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
          })
          .expect(auth.validatePresence(['error', 'error_description', 'state', 'scope']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_scope'))
          .expect(auth.validateScope('offline_access'))
          .expect(auth.validateErrorDescription('requested scope is not whitelisted'));
      });

      it('disallowed response mode', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          response_type: 'code token',
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

      ['request', 'request_uri', 'registration'].forEach((param) => {
        it(`not supported parameter ${param}`, function () {
          const spy = sinon.spy();
          this.provider.once('authorization.error', spy);
          const auth = new this.AuthorizationRequest({
            response_type,
            scope,
            [param]: 'some',
          });

          return this.agent.get(route)
            .query(auth)
            .expect(302)
            .expect(() => {
              expect(spy.calledOnce).to.be.true;
            })
            .expect(auth.validatePresence(['error', 'error_description', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(auth.validateError(`${param}_not_supported`));
        });
      });

      context('when client has more then one redirect_uri', () => {
        before(async function () {
          const client = await this.provider.Client.find('client');
          client.redirectUris.push('https://someOtherUri.com');
        });

        after(async function () {
          const client = await this.provider.Client.find('client');
          client.redirectUris.pop();
        });

        it('missing mandatory parameter redirect_uri', function () {
          const emitSpy = sinon.spy();
          const renderSpy = sinon.spy(i(this.provider).configuration(), 'renderError');
          this.provider.once('authorization.error', emitSpy);
          const auth = new this.AuthorizationRequest({
            response_type,
            scope,
          });
          delete auth.redirect_uri;

          return this.agent.get(route)
            .query(auth)
            .expect(() => {
              renderSpy.restore();
            })
            .expect(400)
            .expect(() => {
              expect(emitSpy.calledOnce).to.be.true;
              expect(renderSpy.calledOnce).to.be.true;
              const renderArgs = renderSpy.args[0];
              expect(renderArgs[1]).to.have.property('error', 'invalid_request');
              expect(renderArgs[1]).to.have.property('error_description', 'missing required parameter \'redirect_uri\'');
              expect(renderArgs[2]).to.be.an.instanceof(InvalidRequest);
            });
        });
      });

      it('missing mandatory parameter response_type', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          scope,
        });
        delete auth.response_type;

        return this.agent.get(route)
          .query(auth)
          .expect(302)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
          })
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_request'))
          .expect(auth.validateErrorDescription('missing required parameter \'response_type\''));
      });

      it('unsupported prompt', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          response_type,
          scope,
          prompt: 'unsupported',
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
          .expect(auth.validateErrorDescription('unsupported prompt value requested'));
      });

      it('supported but not requestable prompt', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          response_type,
          scope,
          prompt: 'unrequestable',
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
          .expect(auth.validateErrorDescription('unsupported prompt value requested'));
      });

      it('bad prompt combination', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          response_type,
          scope,
          prompt: 'none login',
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
          .expect(auth.validateErrorDescription('prompt none must only be used alone'));
      });

      // section-4.1.2.1 RFC6749
      it('missing mandatory parameter client_id', function () {
        const renderSpy = sinon.spy(i(this.provider).configuration(), 'renderError');
        const auth = new this.AuthorizationRequest({
          response_type,
          scope,
        });
        delete auth.client_id;

        return this.agent.get(route)
          .query(auth)
          .expect(() => {
            renderSpy.restore();
          })
          .expect(400)
          .expect(() => {
            expect(renderSpy.calledOnce).to.be.true;
            const renderArgs = renderSpy.args[0];
            expect(renderArgs[1]).to.have.property('error', 'invalid_request');
            expect(renderArgs[1]).to.have.property('error_description', 'missing required parameter \'client_id\'');
            expect(renderArgs[2]).to.be.an.instanceof(InvalidRequest);
          });
      });

      // section-4.1.2.1 RFC6749
      it('unrecognized client_id provided', function () {
        const renderSpy = sinon.spy(i(this.provider).configuration(), 'renderError');
        const auth = new this.AuthorizationRequest({
          response_type,
          scope,
          client_id: 'foobar',
        });

        return this.agent.get(route)
          .query(auth)
          .expect(() => {
            renderSpy.restore();
          })
          .expect(400)
          .expect(() => {
            expect(renderSpy.calledOnce).to.be.true;
            const renderArgs = renderSpy.args[0];
            expect(renderArgs[1]).to.have.property('error', 'invalid_client');
            expect(renderArgs[2]).to.be.an.instanceof(InvalidClient);
          });
      });

      describe('section-4.1.2.1 RFC6749', () => {
        it('validates redirect_uri ad acta [regular error]', function () {
          const renderSpy = sinon.spy(i(this.provider).configuration(), 'renderError');
          const spy = sinon.spy();
          this.provider.on('authorization.error', spy);
          const auth = new this.AuthorizationRequest({
            response_type,
            // scope, => 'openid' required when id_token_hint is provided
            id_token_hint: 'foo',
            redirect_uri: 'https://attacker.example.com/foobar',
          });

          return this.agent.get(route)
            .query(auth)
            .expect(() => {
              this.provider.removeAllListeners('authorization.error');
              renderSpy.restore();
            })
            .expect(() => {
              expect(spy.calledTwice).to.be.true;
            })
            .expect(() => {
              expect(spy.firstCall.calledWithMatch({}, { message: 'invalid_request' })).to.be.true;
              expect(spy.secondCall.calledWithMatch({}, { message: 'redirect_uri_mismatch' })).to.be.true;
            })
            .expect(() => {
              expect(renderSpy.calledOnce).to.be.true;
              const renderArgs = renderSpy.args[0];
              expect(renderArgs[1]).to.have.property('error', 'redirect_uri_mismatch');
              expect(renderArgs[2]).to.be.an.instanceof(RedirectUriMismatch);
            });
        });

        it('validates redirect_uri ad acta [server error]', function () {
          const renderSpy = sinon.spy(i(this.provider).configuration(), 'renderError');
          const authErrorSpy = sinon.spy();
          const serverErrorSpy = sinon.spy();
          this.provider.on('authorization.error', authErrorSpy);
          this.provider.on('server_error', serverErrorSpy);
          sinon.stub(i(this.provider).responseModes, 'has').callsFake(() => { throw new Error('foobar'); });
          const auth = new this.AuthorizationRequest({
            response_type,
            scope,
            response_mode: 'fragment',
            redirect_uri: 'https://attacker.example.com/foobar',
          });

          return this.agent.get(route)
            .query(auth)
            .expect(() => {
              i(this.provider).responseModes.has.restore();
              this.provider.removeAllListeners('authorization.error');
              this.provider.removeAllListeners('server_error');
              renderSpy.restore();
            })
            .expect(() => {
              expect(serverErrorSpy.calledOnce).to.be.true;
              expect(authErrorSpy.calledOnce).to.be.true;
            })
            .expect(() => {
              expect(serverErrorSpy.calledWithMatch({}, { message: 'foobar' })).to.be.true;
              expect(authErrorSpy.calledWithMatch({}, { message: 'redirect_uri_mismatch' })).to.be.true;
            })
            .expect(() => {
              expect(renderSpy.calledOnce).to.be.true;
              const renderArgs = renderSpy.args[0];
              expect(renderArgs[1]).to.have.property('error', 'redirect_uri_mismatch');
              expect(renderArgs[2]).to.be.an.instanceof(RedirectUriMismatch);
            });
        });
      });

      it('unsupported response_type', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          response_type: 'unsupported',
          scope,
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
          })
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('unsupported_response_type'))
          .expect(auth.validateErrorDescription('unsupported response_type requested'));
      });

      it('invalid max_age (negative)', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          response_type,
          scope: 'openid',
          max_age: -1,
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
          .expect(auth.validateErrorDescription('invalid max_age parameter value'));
      });

      it('invalid max_age (MAX_SAFE_INTEGER)', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          response_type,
          scope: 'openid',
          max_age: Number.MAX_SAFE_INTEGER + 1,
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
          .expect(auth.validateErrorDescription('invalid max_age parameter value'));
      });

      if (verb === 'post') {
        it('only supports application/x-www-form-urlencoded', function () {
          const spy = sinon.spy();
          this.provider.once('authorization.error', spy);
          const auth = new this.AuthorizationRequest({
            response_type,
            scope,
          });

          return this.wrap({ route, verb, auth })
            .type('json')
            .expect(400)
            .expect(/only application\/x-www-form-urlencoded content-type bodies are supported on POST \/auth/)
            .expect(/invalid_request/)
            .expect(() => {
              expect(spy.calledOnce).to.be.true;
            });
        });
      }

      it('restricted response_type', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          response_type: 'id_token',
          scope,
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
          })
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('unauthorized_client'))
          .expect(auth.validateErrorDescription('requested response_type is not allowed for this client'));
      });

      it('unsupported response type validation runs before oidc required params', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          response_type: 'id_token token',
          nonce: undefined,
          scope,
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(() => {
            expect(spy.calledOnce).to.be.true;
          })
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('unsupported_response_type'))
          .expect(auth.validateErrorDescription('unsupported response_type requested'));
      });

      it('redirect_uri mismatch', function () {
        const emitSpy = sinon.spy();
        const renderSpy = sinon.spy(i(this.provider).configuration(), 'renderError');
        this.provider.once('authorization.error', emitSpy);
        const auth = new this.AuthorizationRequest({
          response_type,
          scope,
          redirect_uri: 'https://client.example.com/cb/not/registered',
        });

        return this.agent.get(route)
          .query(auth)
          .expect(() => {
            renderSpy.restore();
          })
          .expect(400)
          .expect(() => {
            expect(emitSpy.calledOnce).to.be.true;
            expect(renderSpy.calledOnce).to.be.true;
            const renderArgs = renderSpy.args[0];
            expect(renderArgs[1]).to.have.property('error', 'redirect_uri_mismatch');
            expect(renderArgs[1]).to.have.property('error_description', 'redirect_uri did not match any of the client\'s registered redirect_uris');
            expect(renderArgs[2]).to.be.an.instanceof(RedirectUriMismatch);
          });
      });

      describe('login state specific', () => {
        before(function () { return this.login(); });

        it('malformed id_token_hint', function () {
          const spy = sinon.spy();
          this.provider.once('authorization.error', spy);
          const auth = new this.AuthorizationRequest({
            response_type,
            scope,
            id_token_hint: 'invalid',
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
            .expect(auth.validateErrorDescription(/could not validate id_token_hint/));
        });
      });

      context('exception handling', () => {
        before(async function () {
          sinon.stub(this.provider.Session.prototype, 'accountId').throws();
        });

        after(async function () {
          this.provider.Session.prototype.accountId.restore();
        });

        it('responds with server_error redirect to redirect_uri', function () {
          const auth = new this.AuthorizationRequest({
            response_type,
            prompt: 'none',
            scope,
          });

          const spy = sinon.spy();
          this.provider.once('server_error', spy);

          return this.wrap({ route, verb, auth })
            .expect(302)
            .expect(() => {
              expect(spy.called).to.be.true;
            })
            .expect(auth.validatePresence(['error', 'error_description', 'state']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(auth.validateError('server_error'))
            .expect(auth.validateErrorDescription('oops! something went wrong'));
        });
      });
    });
  });
});
