import { expect } from 'chai';
import sinon from 'sinon';

import bootstrap from '../test_helper.js';

const route = '/auth';
const response_type = 'code id_token token';
const response_mode = 'web_message';
const scope = 'openid';

describe('configuration features.webMessageResponseMode', () => {
  before(bootstrap(import.meta.url));

  before(function () {
    this.provider.use(async (ctx, next) => {
      ctx.set('x-frame-options', 'SAMEORIGIN');
      ctx.set('content-security-policy', "default-src 'none'; frame-ancestors 'self' example.com *.example.net; script-src 'self' 'nonce-foo'; connect-src 'self'; img-src 'self'; style-src 'self';");
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

      it('responds by rendering a an HTML with the client side code and response data [1/4]', async function () {
        const auth = new this.AuthorizationRequest({
          response_type,
          response_mode,
          scope,
        });

        await this.wrap({ route, auth, verb: 'get' })
          .expect(200)
          .expect('cache-control', 'no-store')
          .expect('content-type', 'text/html; charset=utf-8')
          .expect((response) => {
            expect(response.headers['x-frame-options']).not.to.be.ok;
            expect(response.headers['content-security-policy']).not.to.match(/frame-ancestors/);
          })
          .expect(/var data = ({[a-zA-Z0-9"{}~ ,-_]+});/);

        const response = JSON.parse(RegExp.$1);
        expect(response).to.have.keys('redirect_uri', 'response');
        expect(response).to.have.property('redirect_uri', auth.redirect_uri);
        expect(response.response).to.have.keys('id_token', 'state', 'access_token', 'scope', 'expires_in', 'token_type', 'code');
        expect(response.response.id_token).to.be.a('string');
        expect(response.response.expires_in).to.be.a('number');
        expect(response.response.access_token).to.be.a('string');
        expect(response.response.token_type).to.equal('Bearer');
        expect(response.response.state).to.equal(auth.state);
      });

      it('responds by rendering a an HTML with the client side code and response data [2/4]', async function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          response_mode,
          scope,
        });

        await this.wrap({ route, auth, verb: 'get' })
          .expect(200)
          .expect('cache-control', 'no-store')
          .expect('content-type', 'text/html; charset=utf-8')
          .expect((response) => {
            expect(response.headers['x-frame-options']).not.to.be.ok;
            expect(response.headers['content-security-policy']).not.to.match(/frame-ancestors/);
          })
          .expect(/var data = ({[a-zA-Z0-9"{}~ ,-_]+});/);

        const response = JSON.parse(RegExp.$1);
        expect(response).to.have.keys('redirect_uri', 'response');
        expect(response).to.have.property('redirect_uri', auth.redirect_uri);
        expect(response.response).to.have.keys('state', 'code', 'iss');
        expect(response.response.state).to.equal(auth.state);
      });

      it('rejects relay mode with a rendered page', function () {
        const emitSpy = sinon.spy();
        const renderSpy = sinon.spy(i(this.provider).configuration, 'renderError');
        this.provider.once('authorization.error', emitSpy);

        const auth = new this.AuthorizationRequest({
          response_type,
          response_mode,
          web_message_uri: 'anything',
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
            expect(renderArgs[1]).to.have.property('iss');
            expect(renderArgs[1]).to.have.property('error', 'invalid_request');
            expect(renderArgs[1]).to.have.property('error_description', 'Web Message Response Mode Relay Mode is not supported');
          });
      });
    });

    it('handles errors', async function () {
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
        .expect('cache-control', 'no-store')
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
      expect(response).to.have.property('iss');
      expect(response).to.have.property('error', 'login_required');
      expect(response).to.have.property('state', auth.state);
    });
  });
});
