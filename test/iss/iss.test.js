import { describe, before, it } from 'node:test';
import assert from 'node:assert/strict';

import bootstrap from '../test_helper.js';

describe('OAuth 2.0 Authorization Server Issuer Identification', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });

  describe('enriched discovery', () => {
    const fixture1 = Object.create(fixture);

    it('shows the url now', { timeout: 3000 }, () => fixture1.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect((response) => {
          ((actual) => { assert.ok('authorization_response_iss_parameter_supported' in Object(actual)); assert.equal(actual.authorization_response_iss_parameter_supported, true); })(response.body);
        }));
  });

  describe('OAuth 2.0 Authorization Server Issuer Identifier in Authorization Response', () => {
    const fixture2 = Object.create(fixture);

    before(() => fixture2.login(), { timeout: 3000 });

    it('response_type=code', { timeout: 3000 }, () => {
      const auth = new fixture2.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      return fixture2.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validatePresence(['iss'], false))
        .expect(auth.validateClientLocation)
        .expect(auth.validateIss);
    });

    it('response_type=code token', { timeout: 3000 }, () => {
      const auth = new fixture2.AuthorizationRequest({
        response_type: 'code token',
        scope: 'openid',
      });

      return fixture2.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['iss'], false))
        .expect(auth.validateClientLocation)
        .expect(auth.validateIss);
    });

    it('response_type=code id_token', { timeout: 3000 }, () => {
      const auth = new fixture2.AuthorizationRequest({
        response_type: 'code id_token',
        scope: 'openid',
      });

      return fixture2.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['code', 'state', 'id_token']))
        .expect(auth.validateClientLocation);
    });

    it('response_type=code id_token token', { timeout: 3000 }, () => {
      const auth = new fixture2.AuthorizationRequest({
        response_type: 'code id_token token',
        scope: 'openid',
      });

      return fixture2.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['code', 'state', 'id_token', 'access_token', 'token_type', 'expires_in', 'scope']))
        .expect(auth.validateClientLocation);
    });

    it('response_type=id_token token', { timeout: 3000 }, () => {
      const auth = new fixture2.AuthorizationRequest({
        response_type: 'id_token token',
        scope: 'openid',
      });

      return fixture2.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['state', 'id_token', 'access_token', 'token_type', 'expires_in', 'scope']))
        .expect(auth.validateClientLocation);
    });

    it('response_type=id_token', { timeout: 3000 }, () => {
      const auth = new fixture2.AuthorizationRequest({
        response_type: 'id_token',
        scope: 'openid',
      });

      return fixture2.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['state', 'id_token']))
        .expect(auth.validateClientLocation);
    });

    it('response_type=none', { timeout: 3000 }, () => {
      const auth = new fixture2.AuthorizationRequest({
        response_type: 'none',
        scope: 'openid',
      });

      return fixture2.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validatePresence(['state', 'iss']))
        .expect(auth.validateClientLocation)
        .expect(auth.validateIss);
    });

    it('response_mode=jwt', { timeout: 3000 }, () => {
      const auth = new fixture2.AuthorizationRequest({
        response_type: 'code',
        response_mode: 'jwt',
        scope: 'openid',
      });

      return fixture2.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validatePresence(['response']))
        .expect(auth.validateClientLocation);
    });

    it('error with regular response modes', { timeout: 3000 }, () => {
      const auth = new fixture2.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid profile',
      });

      return fixture2.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validatePresence(['error', 'iss'], false))
        .expect(auth.validateClientLocation)
        .expect(auth.validateIss);
    });

    it('error with response_type none', { timeout: 3000 }, () => {
      const auth = new fixture2.AuthorizationRequest({
        response_type: 'none',
        scope: 'openid profile',
      });

      return fixture2.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validatePresence(['error', 'iss'], false))
        .expect(auth.validateClientLocation)
        .expect(auth.validateIss);
    });

    it('error with response_mode=jwt', { timeout: 3000 }, () => {
      const auth = new fixture2.AuthorizationRequest({
        response_type: 'code',
        response_mode: 'jwt',
        scope: 'openid profile',
      });

      return fixture2.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validatePresence(['response']))
        .expect(auth.validateClientLocation);
    });

    it('error with response_mode=jwt fragment', { timeout: 3000 }, () => {
      const auth = new fixture2.AuthorizationRequest({
        response_type: 'code id_token',
        response_mode: 'jwt',
        scope: 'openid profile',
      });

      return fixture2.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['response']))
        .expect(auth.validateClientLocation);
    });
  });
});
