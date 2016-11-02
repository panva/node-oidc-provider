'use strict';

const bootstrap = require('../../test_helper');
const sinon = require('sinon');
const { expect } = require('chai');
const epochTime = require('../../../lib/helpers/epoch_time');

const route = '/auth';

describe('BASIC code', function () {
  before(bootstrap(__dirname)); // provider, agent, AuthorizationRequest, getSession, wrap

  ['get', 'post'].forEach((verb) => {
    describe(`${verb} ${route} with session`, function () {
      before(function () { return this.login(); });

      it('responds with a code in search', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid'
        });

        return this.wrap({ route, verb, auth })
        .expect(302)
        .expect(auth.validatePresence(['code', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation);
      });

      it('responds with a code in fragment', function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          response_mode: 'fragment',
          scope: 'openid'
        });

        return this.wrap({ route, verb, auth })
        .expect(302)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['code', 'state']))
        .expect(auth.validateState)
        .expect(auth.validateClientLocation);
      });
    });

    describe(`${verb} ${route} interactions`, function () {
      beforeEach(function () { return this.login(); });
      after(function () { return this.logout(); });

      it('no account id was found in the session info', function () {
        const session = this.getSession();
        delete session.loginTs;
        delete session.account;

        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid'
        });

        return this.wrap({ route, verb, auth })
        .expect(302)
        .expect(auth.validateInteractionRedirect)
        .expect(auth.validateInteractionError('login_required', 'no_session'));
      });

      it('client not authorized in session yet', function () {
        const session = this.getSession();
        session.authorizations = {};

        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid'
        });

        return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateInteractionRedirect)
          .expect(auth.validateInteractionError('consent_required', 'client_not_authorized'));
      });

      describe('requested by the End-User', function () {
        it('login was requested by the client by prompt parameter', function () {
          const auth = new this.AuthorizationRequest({
            response_type: 'code',
            prompt: 'login',
            scope: 'openid'
          });

          return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateInteractionRedirect)
          .expect(auth.validateInteractionError('login_required', 'login_prompt'));
        });

        it('session is too old for this authorization request', function () {
          const session = this.getSession();
          session.loginTs = epochTime() - 3600; // an hour ago

          const auth = new this.AuthorizationRequest({
            response_type: 'code',
            max_age: '1800', // 30 minutes old session max
            scope: 'openid'
          });

          return this.wrap({ route, verb, auth })
          .expect(302)
          .expect(auth.validateInteractionRedirect)
          .expect(auth.validateInteractionError('login_required', 'max_age'));
        });

        it('session is too old for this client', function* () {
          const client = yield this.provider.Client.find('client');
          client.defaultMaxAge = 1800;

          const session = this.getSession();
          session.loginTs = epochTime() - 3600; // an hour ago

          const auth = new this.AuthorizationRequest({
            response_type: 'code',
            scope: 'openid'
          });

          return this.wrap({ route, verb, auth })
          .expect(() => {
            delete client.defaultMaxAge;
          })
          .expect(302)
          .expect(auth.validateInteractionRedirect)
          .expect(auth.validateInteractionError('login_required', 'max_age'));
        });
      });
    });

    describe(`${verb} ${route} errors`, function () {
      it('dupe parameters', function () {
        // fake a query like this scope=openid&scope=openid
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: ['openid', 'openid']
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
        .expect(auth.validateErrorDescription('parameters must not be provided twice. scope'));
      });

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

      ['request', 'request_uri', 'registration'].forEach((param) => {
        it(`not supported parameter ${param}`, function () {
          const spy = sinon.spy();
          this.provider.once('authorization.error', spy);
          const auth = new this.AuthorizationRequest({
            response_type: 'code',
            scope: 'openid',
            [param]: 'some'
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

      context('when client has more then one redirect_uri', function () {
        before(function* () {
          const client = yield this.provider.Client.find('client');
          client.redirectUris.push('https://someOtherUri.com');
        });

        after(function* () {
          const client = yield this.provider.Client.find('client');
          client.redirectUris.pop();
        });

        it('missing mandatory parameter redirect_uri', function () {
          const emitSpy = sinon.spy();
          const renderSpy = sinon.spy(i(this.provider).configuration(), 'renderError');
          this.provider.once('authorization.error', emitSpy);
          const auth = new this.AuthorizationRequest({
            response_type: 'code',
            scope: 'openid'
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
            const renderArgs = renderSpy.args[0][0];
            expect(renderArgs).to.have.property('error', 'invalid_request');
            expect(renderArgs).to.have.property('error_description', 'missing required parameter(s) redirect_uri');
          });
        });
      });

      ['response_type', 'scope'].forEach((param) => {
        it(`missing mandatory parameter ${param}`, function () {
          const spy = sinon.spy();
          this.provider.once('authorization.error', spy);
          const auth = new this.AuthorizationRequest({
            response_type: 'code',
            scope: 'openid'
          });
          delete auth[param];

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
          .expect(auth.validateErrorDescription(`missing required parameter(s) ${param}`));
        });
      });

      it('unsupported prompt', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
          prompt: 'unsupported'
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
        .expect(auth.validateErrorDescription('invalid prompt value(s) provided. (unsupported)'));
      });

      it('bad prompt combination', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
          prompt: 'none login'
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

      it('unsupported scope', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid and unsupported'
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
        .expect(auth.validateErrorDescription('invalid scope value(s) provided. (and,unsupported)'));
      });

      it('missing openid scope', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'profile'
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
        .expect(auth.validateErrorDescription('openid is required scope'));
      });

      it('invalid use of scope offline_access', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid offline_access'
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
        .expect(auth.validateErrorDescription('offline_access scope requires consent prompt'));
      });

      // section-4.1.2.1 RFC6749
      it('missing mandatory parameter client_id', function () {
        const renderSpy = sinon.spy(i(this.provider).configuration(), 'renderError');
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid'
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
          const renderArgs = renderSpy.args[0][0];
          expect(renderArgs).to.have.property('error', 'invalid_request');
          expect(renderArgs).to.have.property('error_description', 'missing required parameter client_id');
        });
      });

      // section-4.1.2.1 RFC6749
      it('unrecognized client_id provided', function () {
        const renderSpy = sinon.spy(i(this.provider).configuration(), 'renderError');
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
          client_id: 'foobar'
        });

        return this.agent.get(route)
        .query(auth)
        .expect(() => {
          renderSpy.restore();
        })
        .expect(400)
        .expect(() => {
          expect(renderSpy.calledOnce).to.be.true;
          const renderArgs = renderSpy.args[0][0];
          expect(renderArgs).to.have.property('error', 'invalid_client');
        });
      });

      // section-4.1.2.1 RFC6749
      it('validates redirect_uri ad acta even if other errors were encountered beforehand', function () {
        const renderSpy = sinon.spy(i(this.provider).configuration(), 'renderError');
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          // scope: 'openid',
          redirect_uri: 'https://attacker.example.com/foobar'
        });

        return this.agent.get(route)
        .query(auth)
        .expect(() => {
          renderSpy.restore();
        })
        .expect(400)
        .expect(() => {
          expect(renderSpy.calledOnce).to.be.true;
          const renderArgs = renderSpy.args[0][0];
          expect(renderArgs).to.have.property('error', 'redirect_uri_mismatch');
        });
      });

      it('unsupported response_type', function () {
        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          response_type: 'unsupported',
          scope: 'openid'
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
        .expect(auth.validateErrorDescription('response_type not supported. (unsupported)'));
      });

      if (verb === 'post') {
        it('only supports application/x-www-form-urlencoded', function () {
          const spy = sinon.spy();
          this.provider.once('authorization.error', spy);
          const auth = new this.AuthorizationRequest({
            response_type: 'code',
            scope: 'openid'
          });

          return this.wrap({ route, verb, auth })
          .type('json')
          .expect(400)
          .expect(/only application\/x-www-form-urlencoded content-type POST bodies are supported/)
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
          scope: 'openid'
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
        .expect(auth.validateError('restricted_response_type'))
        .expect(auth.validateErrorDescription('response_type not allowed for this client'));
      });

      it('redirect_uri mismatch', function () {
        const emitSpy = sinon.spy();
        const renderSpy = sinon.spy(i(this.provider).configuration(), 'renderError');
        this.provider.once('authorization.error', emitSpy);
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
          redirect_uri: 'http://example.client.dev/notregistered'
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
          const renderArgs = renderSpy.args[0][0];
          expect(renderArgs).to.have.property('error', 'redirect_uri_mismatch');
          expect(renderArgs).to.have.property('error_description', 'redirect_uri did not match any client\'s registered redirect_uri');
        });
      });

      describe('login state specific', function () {
        before(function () { return this.login(); });

        it('malformed id_token_hint', function () {
          const spy = sinon.spy();
          this.provider.once('authorization.error', spy);
          const auth = new this.AuthorizationRequest({
            response_type: 'code',
            scope: 'openid',
            id_token_hint: 'invalid'
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

      context('exception handling', function () {
        before(function () {
          sinon.stub(this.provider.Client, 'find').returns(Promise.reject(new Error()));
        });

        after(function () {
          this.provider.Client.find.restore();
        });

        it('responds with server_error redirect to redirect_uri', function () {
          const auth = new this.AuthorizationRequest({
            response_type: 'code',
            prompt: 'none',
            scope: 'openid'
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
          .expect(auth.validateErrorDescription('oops something went wrong'));
        });
      });
    });
  });
});
