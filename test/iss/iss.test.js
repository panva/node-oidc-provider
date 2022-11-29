import { expect } from 'chai';

import bootstrap from '../test_helper.js';

describe('OAuth 2.0 Authorization Server Issuer Identification', () => {
  before(bootstrap(import.meta.url));

  describe('enriched discovery', () => {
    it('shows the url now', function () {
      return this.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('authorization_response_iss_parameter_supported', true);
        });
    });
  });

  describe('OAuth 2.0 Authorization Server Issuer Identifier in Authorization Response', () => {
    before(function () { return this.login(); });

    it('response_type=code', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
      });

      return this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validatePresence(['iss'], false))
        .expect(auth.validateClientLocation)
        .expect(auth.validateIss);
    });

    it('response_type=code token', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code token',
        scope: 'openid',
      });

      return this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['iss'], false))
        .expect(auth.validateClientLocation)
        .expect(auth.validateIss);
    });

    it('response_type=code id_token', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code id_token',
        scope: 'openid',
      });

      return this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['code', 'state', 'id_token']))
        .expect(auth.validateClientLocation);
    });

    it('response_type=code id_token token', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code id_token token',
        scope: 'openid',
      });

      return this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['code', 'state', 'id_token', 'access_token', 'token_type', 'expires_in', 'scope']))
        .expect(auth.validateClientLocation);
    });

    it('response_type=id_token token', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'id_token token',
        scope: 'openid',
      });

      return this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['state', 'id_token', 'access_token', 'token_type', 'expires_in', 'scope']))
        .expect(auth.validateClientLocation);
    });

    it('response_type=id_token', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'id_token',
        scope: 'openid',
      });

      return this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['state', 'id_token']))
        .expect(auth.validateClientLocation);
    });

    it('response_type=none', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'none',
        scope: 'openid',
      });

      return this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validatePresence(['state', 'iss']))
        .expect(auth.validateClientLocation)
        .expect(auth.validateIss);
    });

    it('response_mode=jwt', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        response_mode: 'jwt',
        scope: 'openid',
      });

      return this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validatePresence(['response']))
        .expect(auth.validateClientLocation);
    });

    it('error with regular response modes', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid profile',
      });

      return this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validatePresence(['error', 'iss'], false))
        .expect(auth.validateClientLocation)
        .expect(auth.validateIss);
    });

    it('error with response_type none', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'none',
        scope: 'openid profile',
      });

      return this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validatePresence(['error', 'iss'], false))
        .expect(auth.validateClientLocation)
        .expect(auth.validateIss);
    });

    it('error with response_mode=jwt', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        response_mode: 'jwt',
        scope: 'openid profile',
      });

      return this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validatePresence(['response']))
        .expect(auth.validateClientLocation);
    });

    it('error with response_mode=jwt fragment', function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code id_token',
        response_mode: 'jwt',
        scope: 'openid profile',
      });

      return this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['response']))
        .expect(auth.validateClientLocation);
    });
  });
});
