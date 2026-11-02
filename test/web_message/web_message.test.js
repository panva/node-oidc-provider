import { describe, before, it, after } from 'node:test';
import assert from 'node:assert/strict';
import sinon from 'sinon';

import bootstrap from '../test_helper.js';

const route = '/auth';
const response_type = 'code id_token token';
const response_mode = 'web_message';
const scope = 'openid';

describe('configuration features.webMessageResponseMode', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  before(() => {
    fixture.provider.use(async (ctx, next) => {
      ctx.set('x-frame-options', 'SAMEORIGIN');
      ctx.set('content-security-policy', "default-src 'none'; frame-ancestors 'self' example.com *.example.net; script-src 'self' 'nonce-foo'; connect-src 'self'; img-src 'self'; style-src 'self';");
      await next();
    });
  }, { timeout: 3000 });

  describe('discovery', () => {
    const fixture1 = Object.create(fixture);

    it('extends the well known config', { timeout: 3000 }, () => fixture1.agent.get('/.well-known/openid-configuration')
        .expect((response) => {
          assert.ok(response.body.response_modes_supported.includes('web_message'));
        }));
  });

  describe('/auth', () => {
    const fixture2 = Object.create(fixture);

    describe('logged in', () => {
      const fixture3 = Object.create(fixture2);

      before(() => fixture3.login(), { timeout: 3000 });
      after(() => fixture3.logout(), { timeout: 3000 });

      it('responds by rendering a an HTML with the client side code and response data [1/4]', { timeout: 3000 }, async () => {
        const auth = new fixture3.AuthorizationRequest({
          response_type,
          response_mode,
          scope,
        });

        await fixture3.wrap({ route, auth, verb: 'get' })
          .expect(200)
          .expect('cache-control', 'no-store')
          .expect('content-type', 'text/html; charset=utf-8')
          .expect((response) => {
            assert.ok(!(response.headers['x-frame-options']));
            assert.doesNotMatch(response.headers['content-security-policy'], /frame-ancestors/);
          })
          .expect(/var data = (\{[^<>&]+?\});/);

        const response = JSON.parse(RegExp.$1);
        assert.deepEqual(new Set(Object.keys(response)), new Set(['redirect_uri', 'response']));
        ((actual) => { assert.ok('redirect_uri' in Object(actual)); assert.equal(actual.redirect_uri, auth.redirect_uri); })(response);
        assert.deepEqual(new Set(Object.keys(response.response)), new Set(['id_token', 'state', 'access_token', 'scope', 'expires_in', 'token_type', 'code']));
        assert.equal(typeof response.response.id_token, 'string');
        assert.equal(typeof response.response.expires_in, 'number');
        assert.equal(typeof response.response.access_token, 'string');
        assert.equal(response.response.token_type, 'Bearer');
        assert.equal(response.response.state, auth.state);
      });

      it('responds by rendering a an HTML with the client side code and response data [2/4]', { timeout: 3000 }, async () => {
        const auth = new fixture3.AuthorizationRequest({
          response_type: 'code',
          response_mode,
          scope,
        });

        await fixture3.wrap({ route, auth, verb: 'get' })
          .expect(200)
          .expect('cache-control', 'no-store')
          .expect('content-type', 'text/html; charset=utf-8')
          .expect((response) => {
            assert.ok(!(response.headers['x-frame-options']));
            assert.doesNotMatch(response.headers['content-security-policy'], /frame-ancestors/);
          })
          .expect(/var data = (\{[^<>&]+?\});/);

        const response = JSON.parse(RegExp.$1);
        assert.deepEqual(new Set(Object.keys(response)), new Set(['redirect_uri', 'response']));
        ((actual) => { assert.ok('redirect_uri' in Object(actual)); assert.equal(actual.redirect_uri, auth.redirect_uri); })(response);
        assert.deepEqual(new Set(Object.keys(response.response)), new Set(['state', 'code', 'iss']));
        assert.equal(response.response.state, auth.state);
      });

      it('rejects relay mode with a rendered page', { timeout: 3000 }, () => {
        const emitSpy = sinon.spy();
        const renderSpy = sinon.spy(i(fixture3.provider).configuration, 'renderError');
        fixture3.provider.once('authorization.error', emitSpy);

        const auth = new fixture3.AuthorizationRequest({
          response_type,
          response_mode,
          web_message_uri: 'anything',
          scope,
        });

        return fixture3.wrap({ route, auth, verb: 'get' })
          .expect(() => {
            renderSpy.restore();
          })
          .expect(400)
          .expect(() => {
            assert.equal(emitSpy.calledOnce, true);
            assert.equal(renderSpy.calledOnce, true);
            const renderArgs = renderSpy.args[0];
            assert.ok('iss' in Object(renderArgs[1]));
            ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request'); })(renderArgs[1]);
            ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'Web Message Response Mode Relay Mode is not supported'); })(renderArgs[1]);
          });
      });
    });

    it('handles errors', { timeout: 3000 }, async () => {
      const auth = new fixture2.AuthorizationRequest({
        response_type,
        prompt: 'none',
        response_mode,
        scope,
      });

      const spy = sinon.spy();
      fixture2.provider.once('authorization.error', spy);

      await fixture2.wrap({ route, auth, verb: 'get' })
        .expect(400)
        .expect('cache-control', 'no-store')
        .expect('content-type', 'text/html; charset=utf-8')
        .expect((response) => {
          assert.ok(!(response.headers['x-frame-options']));
          assert.doesNotMatch(response.headers['content-security-policy'], /frame-ancestors/);
        })
        .expect(() => {
          assert.equal(spy.called, true);
        })
        .expect(/var data = (\{[^<>&]+?\});/);

      const { response } = JSON.parse(RegExp.$1);
      assert.ok('iss' in Object(response));
      ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'login_required'); })(response);
      ((actual) => { assert.ok('state' in Object(actual)); assert.equal(actual.state, auth.state); })(response);
    });

    it('escapes markup in the payload rather than emitting it into the inline script', { timeout: 3000 }, async () => {
      const HOSTILE = '</script><img src=x onerror=alert(1)><!--\u2028\u2029&';
      const auth = new fixture2.AuthorizationRequest({
        response_type, prompt: 'none', response_mode, scope, state: HOSTILE,
      });

      let body;
      await fixture2.wrap({ route, auth, verb: 'get' })
        .expect(400)
        .expect((response) => { body = response.text; });

      const [, payload] = body.match(/var data = (\{[\s\S]*?\});\n/);

      // nothing an HTML parser acts on may survive into the script data
      assert.doesNotMatch(payload, /[<>&\u2028\u2029]/);
      assert.equal(body.match(/<\/script/gi).length, 1);
      assert.ok(!(body.includes('<img')));

      // and it still decodes back to exactly what was sent
      ((actual) => { assert.ok('state' in Object(actual)); assert.equal(actual.state, HOSTILE); })(JSON.parse(payload).response);
      // eslint-disable-next-line no-new-func
      assert.equal(new Function(`return (${payload});`)().response.state, HOSTILE);
    });
  });
});
