'use strict';

const {
  provider,
  agent,
  AuthenticationRequest,
  // getSession,
  wrap
} = require('../test_helper')(__dirname);
// const sinon = require('sinon');
// const { expect } = require('chai');

const route = '/auth';

provider.setupClient();
provider.setupCerts();

['get', 'post'].forEach((verb) => {
  describe(`claimsParameter use via ${verb} ${route}`, function () {
    it('should not be combined with response_type=none', function () {
      const auth = new AuthenticationRequest({
        response_type: 'none',
        scope: 'openid',
        claims: 'something'
      });

      return wrap({ agent, route, verb, auth })
      .expect(302)
      // .expect(auth.validateFragment)
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('invalid_request'))
      .expect(auth.validateErrorDescription('claims parameter should not be combined with response_type none'));
    });

    it('should handle when invalid json is provided', function () {
      const auth = new AuthenticationRequest({
        response_type: 'id_token token',
        scope: 'openid',
        claims: 'something'
      });

      return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('invalid_request'))
      .expect(auth.validateErrorDescription('could not parse the claims parameter JSON'));
    });

    it('should validate an object is passed', function () {
      const auth = new AuthenticationRequest({
        response_type: 'id_token token',
        scope: 'openid',
        claims: 'true'
      });

      return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('invalid_request'))
      .expect(auth.validateErrorDescription('claims parameter should be a JSON object'));
    });

    it('should check accepted properties being present', function () {
      const auth = new AuthenticationRequest({
        response_type: 'id_token token',
        scope: 'openid',
        claims: '{"not_recognized": "does not matter"}'
      });

      return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('invalid_request'))
      .expect(auth.validateErrorDescription('claims parameter should have userinfo or id_token properties'));
    });

    it('should check userinfo property being a simple object', function () {
      const auth = new AuthenticationRequest({
        response_type: 'id_token token',
        scope: 'openid',
        claims: '{"userinfo": "Not an Object"}'
      });

      return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('invalid_request'))
      .expect(auth.validateErrorDescription('claims.userinfo should be an object'));
    });

    it('should check id_token property being a simple object', function () {
      const auth = new AuthenticationRequest({
        response_type: 'id_token token',
        scope: 'openid',
        claims: '{"id_token": "Not an Object"}'
      });

      return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('invalid_request'))
      .expect(auth.validateErrorDescription('claims.id_token should be an object'));
    });

    it('should check that userinfo claims are not specified for id_token requests', function () {
      const auth = new AuthenticationRequest({
        response_type: 'id_token',
        scope: 'openid',
        claims: '{"userinfo": {}}'
      });

      return wrap({ agent, route, verb, auth })
      .expect(302)
      .expect(auth.validateFragment)
      .expect(auth.validatePresence(['error', 'error_description', 'state']))
      .expect(auth.validateState)
      .expect(auth.validateClientLocation)
      .expect(auth.validateError('invalid_request'))
      .expect(auth.validateErrorDescription('claims.userinfo should not be used if access_token is not issued'));
    });
  });
});
