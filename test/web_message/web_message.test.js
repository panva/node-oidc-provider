const { expect } = require('chai');
const sinon = require('sinon');

const bootstrap = require('../test_helper');
const { WebMessageUriMismatch } = require('../../lib/helpers/errors');

const route = '/auth';
const response_type = 'id_token token';
const response_mode = 'web_message';
const scope = 'openid';

describe('configuration features.webMessageResponseMode', () => {
  before(bootstrap(__dirname));

  before(function () {
    this.provider.use(async (ctx, next) => {
      ctx.response.set('X-Frame-Options', 'SAMEORIGIN');
      ctx.response.set('Content-Security-Policy', "default-src 'none'; frame-ancestors 'self' example.com *.example.net; script-src 'self' 'nonce-foo'; connect-src 'self'; img-src 'self'; style-src 'self';");
      await next();
    });
  });

  describe('discovery', () => {
    it('extends the well known config', function () {
      return this.agent.get('/.well-known/openid-configuration')
        .expect((response) => {
          expect(response.body.response_modes_supported).to.include('web_message');
        });
    });
  });

  describe('/auth', () => {
    context('logged in', () => {
      before(function () { return this.login(); });
      after(function () { return this.logout(); });

      it('responds by rendering a an HTML with the client side code and response data [1/2]', async function () {
        const auth = new this.AuthorizationRequest({
          response_type,
          response_mode,
          scope,
        });

        await this.wrap({ route, auth, verb: 'get' })
          .expect(200)
          .expect('pragma', 'no-cache')
          .expect('cache-control', 'no-cache, no-store')
          .expect('content-type', 'text/html; charset=utf-8')
          .expect((response) => {
            expect(response.headers['x-frame-options']).not.to.be.ok;
            expect(response.headers['content-security-policy']).not.to.match(/frame-ancestors/);
          })
          .expect(/var data = ({[a-zA-Z0-9"{}~ ,-_]+});/);

        const response = JSON.parse(RegExp.$1);
        expect(response).to.have.keys('redirect_uri', 'web_message_uri', 'web_message_target', 'response');
        expect(response).to.have.property('redirect_uri', auth.redirect_uri);
        expect(response).to.have.property('web_message_uri', null);
        expect(response).to.have.property('web_message_target', null);
        expect(response.response).to.have.keys('id_token', 'state', 'access_token', 'scope', 'expires_in', 'token_type');
        expect(response.response.id_token).to.be.a('string');
        expect(response.response.expires_in).to.be.a('number');
        expect(response.response.access_token).to.be.a('string');
        expect(response.response.token_type).to.equal('Bearer');
        expect(response.response.state).to.equal(auth.state);
      });

      it('responds by rendering a an HTML with the client side code and response data [2/2]', async function () {
        const auth = new this.AuthorizationRequest({
          response_type,
          response_mode,
          scope,
          web_message_uri: 'https://auth.example.com',
          web_message_target: 'targetID',
        });

        await this.wrap({ route, auth, verb: 'get' })
          .expect(200)
          .expect('pragma', 'no-cache')
          .expect('cache-control', 'no-cache, no-store')
          .expect('content-type', 'text/html; charset=utf-8')
          .expect((response) => {
            expect(response.headers['x-frame-options']).not.to.be.ok;
            expect(response.headers['content-security-policy']).not.to.match(/frame-ancestors/);
          })
          .expect(/var data = ({[a-zA-Z0-9"{}~ ,-_]+});/);

        const response = JSON.parse(RegExp.$1);
        expect(response).to.have.keys('redirect_uri', 'web_message_uri', 'web_message_target', 'response');
        expect(response).to.have.property('redirect_uri', auth.redirect_uri);
        expect(response).to.have.property('web_message_uri', 'https://auth.example.com');
        expect(response).to.have.property('web_message_target', 'targetID');
        expect(response.response).to.have.keys('id_token', 'state', 'access_token', 'scope', 'expires_in', 'token_type');
        expect(response.response.id_token).to.be.a('string');
        expect(response.response.expires_in).to.be.a('number');
        expect(response.response.access_token).to.be.a('string');
        expect(response.response.token_type).to.equal('Bearer');
        expect(response.response.state).to.equal(auth.state);
      });
    });

    context('error handling', () => {
      it('verifies web_message_uri is whitelisted', function () {
        const emitSpy = sinon.spy();
        const renderSpy = sinon.spy(i(this.provider).configuration(), 'renderError');
        this.provider.once('authorization.error', emitSpy);

        const auth = new this.AuthorizationRequest({
          response_type,
          response_mode,
          web_message_uri: 'https://invalid.example.com',
          scope,
        });

        return this.wrap({ route, auth, verb: 'get' })
          .expect(() => {
            renderSpy.restore();
          })
          .expect(400)
          .expect(() => {
            expect(emitSpy.calledOnce).to.be.true;
            expect(renderSpy.calledOnce).to.be.true;
            const renderArgs = renderSpy.args[0];
            expect(renderArgs[1]).to.have.property('error', 'web_message_uri_mismatch');
            expect(renderArgs[1]).to.have.property('error_description', "web_message_uri did not match any client's registered web_message_uris");
            expect(renderArgs[2]).to.be.an.instanceof(WebMessageUriMismatch);
          });
      });

      it('validates web_message_uri ad acta [regular error]', function () {
        const renderSpy = sinon.spy(i(this.provider).configuration(), 'renderError');
        const spy = sinon.spy();
        this.provider.on('authorization.error', spy);
        const auth = new this.AuthorizationRequest({
          response_type,
          response_mode,
          // scope,
          web_message_uri: 'https://invalid.example.com',
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
            expect(spy.secondCall.calledWithMatch({}, { message: 'web_message_uri_mismatch' })).to.be.true;
          })
          .expect(() => {
            expect(renderSpy.calledOnce).to.be.true;
            const renderArgs = renderSpy.args[0];
            expect(renderArgs[1]).to.have.property('error', 'web_message_uri_mismatch');
            expect(renderArgs[2]).to.be.an.instanceof(WebMessageUriMismatch);
          });
      });

      it('validates web_message_uri ad acta [server error]', function () {
        const renderSpy = sinon.spy(i(this.provider).configuration(), 'renderError');
        const authErrorSpy = sinon.spy();
        const serverErrorSpy = sinon.spy();
        this.provider.on('authorization.error', authErrorSpy);
        this.provider.on('server_error', serverErrorSpy);
        sinon.stub(i(this.provider).responseModes, 'has').callsFake(() => { throw new Error('foobar'); });
        const auth = new this.AuthorizationRequest({
          response_type,
          response_mode,
          scope,
          web_message_uri: 'https://invalid.example.com',
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
            expect(authErrorSpy.calledWithMatch({}, { message: 'web_message_uri_mismatch' })).to.be.true;
          })
          .expect(() => {
            expect(renderSpy.calledOnce).to.be.true;
            const renderArgs = renderSpy.args[0];
            expect(renderArgs[1]).to.have.property('error', 'web_message_uri_mismatch');
            expect(renderArgs[2]).to.be.an.instanceof(WebMessageUriMismatch);
          });
      });

      it('responds by rendering a self-submitting form with the error', async function () {
        const auth = new this.AuthorizationRequest({
          response_type,
          prompt: 'none',
          response_mode,
          scope,
        });

        const spy = sinon.spy();
        this.provider.once('authorization.error', spy);

        await this.wrap({ route, auth, verb: 'get' })
          .expect(400)
          .expect('pragma', 'no-cache')
          .expect('cache-control', 'no-cache, no-store')
          .expect('content-type', 'text/html; charset=utf-8')
          .expect((response) => {
            expect(response.headers['x-frame-options']).not.to.be.ok;
            expect(response.headers['content-security-policy']).not.to.match(/frame-ancestors/);
          })
          .expect(() => {
            expect(spy.called).to.be.true;
          })
          .expect(/var data = ({[a-zA-Z0-9"{} ,-_]+});/);

        const { response } = JSON.parse(RegExp.$1);
        expect(response).to.have.property('error', 'login_required');
        expect(response).to.have.property('state', auth.state);
      });

      context('[exception]', () => {
        before(async function () {
          sinon.stub(this.provider.Session.prototype, 'accountId').throws();
        });

        after(async function () {
          this.provider.Session.prototype.accountId.restore();
        });

        it('responds by rendering a self-submitting form with the exception', async function () {
          const auth = new this.AuthorizationRequest({
            response_type,
            prompt: 'none',
            response_mode,
            scope,
          });

          const spy = sinon.spy();
          this.provider.once('server_error', spy);

          await this.wrap({ route, auth, verb: 'get' })
            .expect(500)
            .expect('pragma', 'no-cache')
            .expect('cache-control', 'no-cache, no-store')
            .expect('content-type', 'text/html; charset=utf-8')
            .expect((response) => {
              expect(response.headers['x-frame-options']).not.to.be.ok;
              expect(response.headers['content-security-policy']).not.to.match(/frame-ancestors/);
            })
            .expect(() => {
              expect(spy.called).to.be.true;
            })
            .expect(/var data = ({[a-zA-Z0-9"!{} ,-_]+});/);

          const { response } = JSON.parse(RegExp.$1);
          expect(response).to.have.property('error', 'server_error');
          expect(response).to.have.property('state', auth.state);
        });
      });
    });
  });
});
