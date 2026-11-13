import { describe, before, it, beforeEach, afterEach } from 'node:test';
import { SignJWT } from 'jose';

import bootstrap from '../test_helper.js';
import epochTime from '../../lib/helpers/epoch_time.js';

import { keypair } from './fapi-final.config.js';

describe('Financial-grade API Security Profile 1.0 - Part 2: Advanced (FINAL) behaviours', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture, { config: 'fapi-final' }), { timeout: 3000 });

  describe('userinfo', () => {
    const fixture1 = Object.create(fixture);

    before(() => fixture1.login(), { timeout: 3000 });

    it('ignores query string bearer tokens', { timeout: 3000 }, async () => {
      const at = await new fixture1.provider.AccessToken({
        client: await fixture1.provider.Client.find('client'),
        accountId: fixture1.loggedInAccountId,
        grantId: fixture1.getGrantId(),
        scope: 'openid',
      }).save();

      await fixture1.agent.get('/me')
        .query({ access_token: at })
        .expect(fixture1.failWith(401, 'invalid_token', 'no access token provided'));

      await fixture1.agent.get('/me')
        .auth(at, { type: 'bearer' })
        .query({ access_token: 'ignored-query-token' })
        .expect(200)
        .expect({ sub: fixture1.loggedInAccountId });

      await fixture1.agent.post('/me')
        .type('form')
        .send({ access_token: at })
        .query({ access_token: 'ignored-query-token' })
        .expect(200)
        .expect({ sub: fixture1.loggedInAccountId });
    });
  });

  describe('FAPI 1.0 Final Authorization Request', () => {
    const fixture2 = Object.create(fixture);

    beforeEach(() => fixture2.login(), { timeout: 3000 });
    afterEach(() => fixture2.logout(), { timeout: 3000 });

    it('does not require PKCE to be used on the authorization endpoint', { timeout: 3000 }, () => {
      const auth = new fixture2.AuthorizationRequest({
        scope: 'openid',
        client_id: 'client',
        response_type: 'code id_token',
        nonce: 'foo',
        code_challenge_method: undefined,
        code_challenge: undefined,
      });

      return fixture2.wrap({
        agent: fixture2.agent,
        route: '/auth',
        verb: 'get',
        auth,
      })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['id_token', 'code', 'state']))
        .expect(auth.validateClientLocation);
    });

    it('requires PKCE to be used when PAR is used', { timeout: 3000 }, () => fixture2.agent.post('/request')
        .auth('client', 'secret')
        .send({
          scope: 'openid',
          client_id: 'client',
          response_type: 'code',
          response_mode: 'jwt',
          code_challenge_method: undefined,
          code_challenge: undefined,
          nonce: 'foo',
        })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_request',
          error_description: 'Authorization Server policy requires PKCE to be used for this request',
        }));

    it('requires jwt response mode to be used when id token is not issued by authorization endpoint', { timeout: 3000 }, () => {
      const auth = new fixture2.AuthorizationRequest({
        scope: 'openid',
        client_id: 'client',
        response_type: 'code',
        nonce: 'foo',
      });

      return fixture2.wrap({
        agent: fixture2.agent,
        route: '/auth',
        verb: 'get',
        auth,
      })
        .expect(303)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_request'))
        .expect(auth.validateErrorDescription('requested response_mode is not allowed for this client or request'));
    });

    it('requires jwt response mode to be used when id token is not issued by authorization endpoint (JAR)', { timeout: 3000 }, async () => {
      const request = await new SignJWT({
        scope: 'openid',
        client_id: 'client',
        response_type: 'code',
        nonce: 'foo',
        iss: 'client',
        aud: fixture2.provider.issuer,
        exp: epochTime() + 60,
        nbf: epochTime(),
      }).setProtectedHeader({ alg: 'ES256' }).sign(keypair.privateKey);

      const auth = new fixture2.AuthorizationRequest({
        request,
        state: undefined,
      });

      return fixture2.wrap({
        agent: fixture2.agent,
        route: '/auth',
        verb: 'get',
        auth,
      })
        .expect(303)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_request'))
        .expect(auth.validateErrorDescription('requested response_mode is not allowed for this client or request'));
    });
  });

  describe('Request Object', () => {
    const fixture3 = Object.create(fixture);

    beforeEach(() => fixture3.login(), { timeout: 3000 });
    afterEach(() => fixture3.logout(), { timeout: 3000 });

    it('still works', { timeout: 3000 }, async () => {
      const request = await new SignJWT({
        client_id: 'client',
        iss: 'client',
        scope: 'openid',
        response_type: 'code id_token',
        nonce: 'foo',
        redirect_uri: 'https://client.example.com/cb',
        aud: fixture3.provider.issuer,
        state: 'foo',
        exp: epochTime() + 60,
        nbf: epochTime(),
      }).setProtectedHeader({ alg: 'ES256' }).sign(keypair.privateKey);

      const auth = new fixture3.AuthorizationRequest({
        request,
        scope: 'openid',
        client_id: 'client',
        response_type: 'code id_token',
        nonce: 'foo',
        state: 'foo',
      });

      return fixture3.wrap({
        agent: fixture3.agent,
        route: '/auth',
        verb: 'get',
        auth,
      })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['id_token', 'code', 'state']))
        .expect(auth.validateClientLocation);
    });

    it('requires exp to be provided in the Request Object', { timeout: 3000 }, async () => {
      const request = await new SignJWT({
        aud: fixture3.provider.issuer,
        // exp: epochTime() + 60,
        nbf: epochTime(),
        iss: 'client',
        client_id: 'client',
        scope: 'openid',
        response_type: 'code id_token',
        nonce: 'foo',
      }).setProtectedHeader({ alg: 'ES256' }).sign(keypair.privateKey);

      const auth = new fixture3.AuthorizationRequest({
        request,
        scope: 'openid',
        client_id: 'client',
        response_type: 'code id_token',
        nonce: 'foo',
      });

      return fixture3.wrap({
        agent: fixture3.agent,
        route: '/auth',
        verb: 'get',
        auth,
      })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_request_object'))
        .expect(auth.validateErrorDescription("Request Object is missing the 'exp' claim"));
    });

    it('requires nbf to be provided in the Request Object', { timeout: 3000 }, async () => {
      const request = await new SignJWT({
        aud: fixture3.provider.issuer,
        exp: epochTime() + 60,
        // nbf: epochTime(),
        client_id: 'client',
        scope: 'openid',
        iss: 'client',
        response_type: 'code id_token',
        nonce: 'foo',
      }).setProtectedHeader({ alg: 'ES256' }).sign(keypair.privateKey);

      const auth = new fixture3.AuthorizationRequest({
        request,
        scope: 'openid',
        client_id: 'client',
        response_type: 'code id_token',
        nonce: 'foo',
      });

      return fixture3.wrap({
        agent: fixture3.agent,
        route: '/auth',
        verb: 'get',
        auth,
      })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_request_object'))
        .expect(auth.validateErrorDescription("Request Object is missing the 'nbf' claim"));
    });

    it('requires nbf to be no more than 3600 from exp', { timeout: 3000 }, async () => {
      const request = await new SignJWT({
        exp: epochTime() + 60,
        nbf: epochTime() - 3600,
        aud: fixture3.provider.issuer,
        client_id: 'client',
        scope: 'openid',
        iss: 'client',
        response_type: 'code id_token',
        nonce: 'foo',
      }).setProtectedHeader({ alg: 'ES256' }).sign(keypair.privateKey);

      const auth = new fixture3.AuthorizationRequest({
        request,
        scope: 'openid',
        client_id: 'client',
        response_type: 'code id_token',
        nonce: 'foo',
      });

      return fixture3.wrap({
        agent: fixture3.agent,
        route: '/auth',
        verb: 'get',
        auth,
      })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_request_object'))
        .expect(auth.validateErrorDescription("Request Object 'exp' claim too far from 'nbf' claim"));
    });
  });
});
