import { describe, before, it } from 'node:test';
import assert from 'node:assert/strict';
import sinon from 'sinon';

import bootstrap from '../test_helper.js';
import { normalize } from '../../lib/helpers/user_codes.js';

const route = '/device/auth';

describe('device_authorization_endpoint', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  it('rejects other than application/x-www-form-urlencoded', { timeout: 3000 }, () => {
    const spy = sinon.spy();
    fixture.provider.once('device_authorization.error', spy);

    return fixture.agent.post(route)
      .send({
        client_id: 'client',
        scope: 'openid',
      })
      .expect(400)
      .expect('content-type', /application\/json/)
      .expect(() => {
        assert.equal(spy.calledOnce, true);
      })
      .expect({
        error: 'invalid_request',
        error_description: 'only application/x-www-form-urlencoded content-type bodies are supported on POST /device/auth',
      });
  });

  describe('client validation', () => {
    const fixture1 = Object.create(fixture);

    it('only responds to clients with urn:ietf:params:oauth:grant-type:device_code enabled', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture1.provider.once('device_authorization.error', spy);

      return fixture1.agent.post(route)
        .send({
          client_id: 'client-not-allowed',
        })
        .type('form')
        .expect(400)
        .expect('content-type', /application\/json/)
        .expect({
          error: 'invalid_request',
          error_description: 'urn:ietf:params:oauth:grant-type:device_code is not allowed for this client',
        })
        .expect(() => {
          assert.equal(spy.calledOnce, true);
        });
    });

    it('rejects invalid clients', { timeout: 3000 }, () => {
      const spy = sinon.spy();
      fixture1.provider.once('device_authorization.error', spy);

      return fixture1.agent.post(route)
        .send({
          client_id: 'not-found-client',
        })
        .type('form')
        .expect(401)
        .expect('content-type', /application\/json/)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
        })
        .expect({
          error: 'invalid_client',
          error_description: 'client authentication failed',
        });
    });
  });

  describe('param validation', () => {
    const fixture2 = Object.create(fixture);

    ['request', 'request_uri', 'registration'].forEach((param) => {
      it(`check for not supported parameter ${param}`, { timeout: 3000 }, () => {
        const spy = sinon.spy();
        fixture2.provider.once('device_authorization.error', spy);

        return fixture2.agent.post(route)
          .send({
            client_id: 'client',
            [param]: 'some',
          })
          .type('form')
          .expect(400)
          .expect('content-type', /application\/json/)
          .expect(() => {
            assert.equal(spy.calledOnce, true);
          })
          .expect({
            error: `${param}_not_supported`,
          });
      });
    });
  });

  it('responds with json 200', { timeout: 3000 }, async () => {
    const spy = sinon.spy();
    fixture.provider.once('device_authorization.success', spy);
    let response;

    await fixture.agent.post(route)
      .send({
        client_id: 'client',
        scope: 'openid',
        extra: 'included',
        extra2: 'defaulted',
        claims: JSON.stringify({ userinfo: { email: null } }),
        redirect_uri: 'https://rp.example.com/cb/not/included',
        response_mode: 'not included',
        state: 'not included',
        response_type: 'not included',
        code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        code_challenge_method: 'S256',
      })
      .type('form')
      .expect(200)
      .expect('content-type', /application\/json/)
      .expect(() => {
        assert.equal(spy.calledOnce, true);
      })
      .expect(({ body }) => {
        assert.deepEqual(new Set(Object.keys(body)), new Set([
          'device_code',
          'user_code',
          'verification_uri',
          'verification_uri_complete',
          'expires_in',
        ]));
        assert.equal(body.verification_uri_complete, `${body.verification_uri}?user_code=${body.user_code}`);
        ((actual) => { assert.ok('verification_uri' in Object(actual)); assert.match(actual.verification_uri, /\/device$/); })(body);
        ((actual) => { assert.ok('expires_in' in Object(actual)); ((value) => { assert.equal(typeof value, 'number'); assert.ok(Math.abs((value) - (600)) <= (1)); })(actual.expires_in); })(body);
        response = body;
      });

    const dc = await fixture.provider.DeviceCode.find(response.device_code);
    assert.ok(dc);
    ((actual) => { assert.ok('clientId' in Object(actual)); assert.equal(actual.clientId, 'client'); })(dc);
    ((actual) => { assert.ok('userCode' in Object(actual)); assert.equal(typeof actual.userCode, 'string'); assert.equal(actual.userCode, normalize(response.user_code)); })(dc);
    ((actual) => { assert.ok('params' in Object(actual)); assert.equal(Object.prototype.toString.call(actual.params), '[object Object]'); })(dc);
    ((actual) => { assert.ok('client_id' in Object(actual)); assert.equal(actual.client_id, 'client'); })(dc.params);
    ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, 'openid'); })(dc.params);
    ((actual) => { assert.ok('extra' in Object(actual)); assert.equal(actual.extra, 'included'); })(dc.params);
    ((actual) => { assert.ok('claims' in Object(actual)); assert.equal(actual.claims, JSON.stringify({ userinfo: { email: null } })); })(dc.params);
    assert.ok(!('redirect_uri' in Object(dc.params)));
    assert.ok(!('response_type' in Object(dc.params)));
    assert.ok(!('state' in Object(dc.params)));
    assert.ok(!('response_mode' in Object(dc.params)));
  });

  it('does not require PAR for clients with require_pushed_authorization_requests', { timeout: 3000 }, () => fixture.agent.post(route)
      .send({
        client_id: 'client-par-required',
        scope: 'openid',
      })
      .type('form')
      .expect(200)
      .expect('content-type', /application\/json/)
      .expect(({ body }) => {
        assert.deepEqual(new Set(Object.keys(body)), new Set([
          'device_code',
          'user_code',
          'verification_uri',
          'verification_uri_complete',
          'expires_in',
        ]));
      }));

  it('handles regular client auth', { timeout: 3000 }, () => fixture.agent.post(route)
      .auth('client-basic-auth', 'secret')
      .type('form')
      .expect(200)
      .expect('content-type', /application\/json/)
      .expect(({ body }) => {
        assert.deepEqual(new Set(Object.keys(body)), new Set([
          'device_code',
          'user_code',
          'verification_uri',
          'verification_uri_complete',
          'expires_in',
        ]));
      }));

  it('populates ctx.oidc.entities', { timeout: 3000 }, (_t, done) => {
    fixture.assertOnce((ctx) => {
      assert.deepEqual(new Set(Object.keys(ctx.oidc.entities)), new Set(['Client', 'DeviceCode']));
    }, done);

    fixture.agent.post(route)
      .send({
        client_id: 'client',
        scope: 'openid',
        code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        code_challenge_method: 'S256',
      })
      .type('form')
      .end(() => {});
  });
});
