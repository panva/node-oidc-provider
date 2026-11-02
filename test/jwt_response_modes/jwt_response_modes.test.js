import { describe, before, it, after } from 'node:test';
import assert from 'node:assert/strict';
import * as url from 'node:url';

import sinon from 'sinon';

import bootstrap from '../test_helper.js';
import { decode } from '../../lib/helpers/jwt.js';

const route = '/auth';

describe('configuration features.jwtResponseModes', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  describe('discovery', () => {
    const fixture1 = Object.create(fixture);

    it('extends the well known config', { timeout: 3000 }, () => fixture1.agent.get('/.well-known/openid-configuration')
        .expect((response) => {
          assert.ok('authorization_signing_alg_values_supported' in Object(response.body));
          assert.ok('authorization_encryption_alg_values_supported' in Object(response.body));
          assert.ok('authorization_encryption_enc_values_supported' in Object(response.body));
          assert.ok(response.body.response_modes_supported.includes('jwt'));
          assert.ok(response.body.response_modes_supported.includes('query.jwt'));
          assert.ok(response.body.response_modes_supported.includes('fragment.jwt'));
          assert.ok(response.body.response_modes_supported.includes('form_post.jwt'));
          assert.ok(response.body.response_modes_supported.includes('web_message.jwt'));
        }));
  });

  describe('response_mode=jwt', () => {
    const fixture2 = Object.create(fixture);

    before(() => fixture2.login(), { timeout: 3000 });
    after(() => fixture2.logout(), { timeout: 3000 });

    it('defaults to fragment for implicit and hybrid response types', { timeout: 3000 }, async () => {
      const auth = new fixture2.AuthorizationRequest({
        response_type: 'id_token token',
        response_mode: 'jwt',
        scope: 'openid',
      });

      await fixture2.wrap({ route, auth, verb: 'get' })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['response']))
        .expect(auth.validateClientLocation)
        .expect(({ headers: { location } }) => {
          const { query: { response } } = url.parse(location, true);
          const { payload } = decode(response);
          assert.ok(['id_token', 'access_token', 'expires_in', 'token_type'].every((key) => Object.keys(payload).includes(key)));
          ((actual) => { assert.ok('exp' in Object(actual)); assert.equal(typeof actual.exp, 'number'); })(payload);
          ((actual) => { assert.ok('aud' in Object(actual)); assert.equal(actual.aud, 'client'); })(payload);
          ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, 'openid'); })(payload);
          ((actual) => { assert.ok('state' in Object(actual)); assert.equal(actual.state, auth.state); })(payload);
          ((actual) => { assert.ok('iss' in Object(actual)); assert.equal(actual.iss, fixture2.provider.issuer); })(payload);
        });
    });

    it('defaults to query for code response type', { timeout: 3000 }, async () => {
      const auth = new fixture2.AuthorizationRequest({
        response_type: 'code',
        response_mode: 'jwt',
        scope: 'openid',
      });

      await fixture2.wrap({ route, auth, verb: 'get' })
        .expect(303)
        .expect(auth.validatePresence(['response']))
        .expect(auth.validateClientLocation)
        .expect(({ headers: { location } }) => {
          const { query: { response } } = url.parse(location, true);
          const { payload } = decode(response);
          assert.ok(['code'].every((key) => Object.keys(payload).includes(key)));
          ((actual) => { assert.ok('exp' in Object(actual)); assert.equal(typeof actual.exp, 'number'); })(payload);
          ((actual) => { assert.ok('aud' in Object(actual)); assert.equal(actual.aud, 'client'); })(payload);
          assert.ok(!('scope' in Object(payload)));
          ((actual) => { assert.ok('state' in Object(actual)); assert.equal(actual.state, auth.state); })(payload);
          ((actual) => { assert.ok('iss' in Object(actual)); assert.equal(actual.iss, fixture2.provider.issuer); })(payload);
        });
    });

    it('defaults to query for none response type', { timeout: 3000 }, async () => {
      const auth = new fixture2.AuthorizationRequest({
        response_type: 'none',
        response_mode: 'jwt',
        scope: 'openid',
      });

      await fixture2.wrap({ route, auth, verb: 'get' })
        .expect(303)
        .expect(auth.validatePresence(['response']))
        .expect(auth.validateClientLocation)
        .expect(({ headers: { location } }) => {
          const { query: { response } } = url.parse(location, true);
          const { payload } = decode(response);
          assert.deepEqual(new Set(Object.keys(payload)), new Set(['exp', 'aud', 'state', 'iss']));
        });
    });

    describe('when secret is expired', () => {
      const fixture3 = Object.create(fixture2);

      it('defaults to fragment for implicit and hybrid response types', { timeout: 3000 }, async () => {
        const auth = new fixture3.AuthorizationRequest({
          client_id: 'client-expired',
          response_type: 'id_token token',
          response_mode: 'jwt',
          scope: 'openid',
        });

        await fixture3.wrap({ route, auth, verb: 'get' })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_client'))
          .expect(auth.validateErrorDescription('client secret is expired, cannot issue a JWT Authorization response'));
      });

      it('defaults to query for code response type', { timeout: 3000 }, async () => {
        const auth = new fixture3.AuthorizationRequest({
          response_type: 'code',
          response_mode: 'jwt',
          scope: 'openid',
          client_id: 'client-expired',
        });

        await fixture3.wrap({ route, auth, verb: 'get' })
          .expect(303)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_client'))
          .expect(auth.validateErrorDescription('client secret is expired, cannot issue a JWT Authorization response'));
      });

      it('defaults to query for none response type', { timeout: 3000 }, async () => {
        const auth = new fixture3.AuthorizationRequest({
          response_type: 'none',
          response_mode: 'jwt',
          scope: 'openid',
          client_id: 'client-expired',
        });

        await fixture3.wrap({ route, auth, verb: 'get' })
          .expect(303)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_client'))
          .expect(auth.validateErrorDescription('client secret is expired, cannot issue a JWT Authorization response'));
      });
    });
  });

  describe('response_mode=query.jwt', () => {
    const fixture4 = Object.create(fixture);

    before(() => fixture4.login(), { timeout: 3000 });
    after(() => fixture4.logout(), { timeout: 3000 });

    it('is forbidden for implicit and hybrid response types unless encrypted', { timeout: 3000 }, async () => {
      const auth = new fixture4.AuthorizationRequest({
        response_type: 'id_token token',
        response_mode: 'query.jwt',
        scope: 'openid',
      });

      await fixture4.wrap({ route, auth, verb: 'get' })
        .expect(303)
        .expect(auth.validatePresence(['response']))
        .expect(auth.validateClientLocation)
        .expect(({ headers: { location } }) => {
          const { query: { response } } = url.parse(location, true);
          const { payload } = decode(response);
          assert.deepEqual(new Set(Object.keys(payload)), new Set(['error', 'error_description', 'state', 'aud', 'exp', 'iss']));
          assert.deepEqual(payload.error, 'invalid_request');
          assert.deepEqual(payload.error_description, 'requested response_mode is not allowed for the requested response_type unless encrypted');
        });
    });

    it('uses the query part when expired', { timeout: 3000 }, async () => {
      const auth = new fixture4.AuthorizationRequest({
        response_type: 'id_token token',
        response_mode: 'query.jwt',
        scope: 'openid',
        client_id: 'client-expired',
      });

      await fixture4.wrap({ route, auth, verb: 'get' })
        .expect(303)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_client'))
        .expect(auth.validateErrorDescription('client secret is expired, cannot issue a JWT Authorization response'));
    });

    it('is allowed for implicit and hybrid response types if encrypted', { timeout: 3000 }, async () => {
      const spy = sinon.spy();
      fixture4.provider.once('authorization.success', spy);
      const auth = new fixture4.AuthorizationRequest({
        client_id: 'client-encrypted',
        response_type: 'id_token token',
        response_mode: 'query.jwt',
        scope: 'openid',
      });

      await fixture4.wrap({ route, auth, verb: 'get' })
        .expect(303)
        .expect(auth.validatePresence(['response']))
        .expect(auth.validateClientLocation);

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
    });

    it('is allowed for code response type', { timeout: 3000 }, async () => {
      const auth = new fixture4.AuthorizationRequest({
        response_type: 'code',
        response_mode: 'query.jwt',
        scope: 'openid',
      });

      await fixture4.wrap({ route, auth, verb: 'get' })
        .expect(303)
        .expect(auth.validatePresence(['response']))
        .expect(auth.validateClientLocation)
        .expect(({ headers: { location } }) => {
          const { query: { response } } = url.parse(location, true);
          const { payload } = decode(response);
          assert.ok(['code'].every((key) => Object.keys(payload).includes(key)));
          ((actual) => { assert.ok('exp' in Object(actual)); assert.equal(typeof actual.exp, 'number'); })(payload);
          ((actual) => { assert.ok('aud' in Object(actual)); assert.equal(actual.aud, 'client'); })(payload);
          assert.ok(!('scope' in Object(payload)));
          ((actual) => { assert.ok('state' in Object(actual)); assert.equal(actual.state, auth.state); })(payload);
          ((actual) => { assert.ok('iss' in Object(actual)); assert.equal(actual.iss, fixture4.provider.issuer); })(payload);
        });
    });

    it('is allowed for none response type', { timeout: 3000 }, async () => {
      const auth = new fixture4.AuthorizationRequest({
        response_type: 'none',
        response_mode: 'query.jwt',
        scope: 'openid',
      });

      await fixture4.wrap({ route, auth, verb: 'get' })
        .expect(303)
        .expect(auth.validatePresence(['response']))
        .expect(auth.validateClientLocation)
        .expect(({ headers: { location } }) => {
          const { query: { response } } = url.parse(location, true);
          const { payload } = decode(response);
          assert.deepEqual(new Set(Object.keys(payload)), new Set(['exp', 'aud', 'state', 'iss']));
        });
    });
  });

  Object.entries({
    'query.jwt': 303,
    'fragment.jwt': 303,
    'form_post.jwt': 400,
    'web_message.jwt': 400,
  }).forEach(([mode, errStatus]) => {
    describe(`${mode} err handling`, () => {
      const fixture5 = Object.create(fixture);

      it(`responds with a ${errStatus}`, { timeout: 3000 }, () => {
        const auth = new fixture5.AuthorizationRequest({
          response_type: 'code',
          prompt: 'none',
          response_mode: mode,
          scope: 'openid',
        });

        const spy = sinon.spy();
        fixture5.provider.once('authorization.error', spy);

        return fixture5.wrap({ route, verb: 'get', auth })
          .expect(errStatus)
          .expect(() => {
            assert.equal(spy.called, true);
          });
      });

      it('handles expired secrets', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture5.provider.once('authorization.error', spy);

        const auth = new fixture5.AuthorizationRequest({
          response_type: 'code',
          response_mode: mode,
          scope: 'openid',
          client_id: 'client-expired',
        });

        await fixture5.wrap({ route, auth, verb: 'get' })
          .expect(errStatus)
          .expect(() => {
            assert.equal(spy.called, true);
            ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_client'); })(spy.args[0][1]);
            ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, 'client secret is expired, cannot issue a JWT Authorization response'); })(spy.args[0][1]);
          });
      });
    });
  });
});
