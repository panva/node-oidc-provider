import { SignJWT } from 'jose';

import bootstrap from '../test_helper.js';
import epochTime from '../../lib/helpers/epoch_time.js';

import { keypair } from './fapi-id2.config.js';

describe('Financial-grade API - Part 2: Read and Write API Security Profile (ID2) behaviours', () => {
  before(bootstrap(import.meta.url, { config: 'fapi-id2' }));

  describe('userinfo', () => {
    before(function () { return this.login(); });

    it('does not allow query string bearer token', async function () {
      const at = await new this.provider.AccessToken({
        client: await this.provider.Client.find('client'),
        accountId: this.loggedInAccountId,
        grantId: this.getGrantId(),
        scope: 'openid',
      }).save();

      await this.agent.get('/me')
        .query({ access_token: at })
        .expect(this.failWith(400, 'invalid_request', 'access tokens must not be provided via query parameter'));

      await this.agent.get('/me')
        .auth(at, { type: 'bearer' })
        .expect(200)
        .expect({ sub: this.loggedInAccountId });

      await this.agent.post('/me')
        .type('form')
        .send({ access_token: at })
        .expect(200)
        .expect({ sub: this.loggedInAccountId });
    });
  });

  describe('FAPI Mode Authorization Request', () => {
    beforeEach(function () { return this.login(); });
    afterEach(function () { return this.logout(); });

    it('requires jwt response mode to be used when id token is not issued by authorization endpoint', function () {
      const auth = new this.AuthorizationRequest({
        scope: 'openid',
        client_id: 'client',
        response_type: 'code',
        nonce: 'foo',
      });

      return this.wrap({
        agent: this.agent,
        route: '/auth',
        verb: 'get',
        auth,
      })
        .expect(303)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_request'))
        .expect(auth.validateErrorDescription('requested response_mode not allowed for the requested response_type in FAPI 1.0 ID2'));
    });

    it('requires jwt response mode to be used when id token is not issued by authorization endpoint (JAR)', async function () {
      const request = await new SignJWT({
        scope: 'openid',
        client_id: 'client',
        response_type: 'code',
        nonce: 'foo',
        exp: epochTime() + 60,
      }).setProtectedHeader({ alg: 'ES256' }).sign(keypair.privateKey);

      const auth = new this.AuthorizationRequest({
        request,
        state: undefined,
      });

      return this.wrap({
        agent: this.agent,
        route: '/auth',
        verb: 'get',
        auth,
      })
        .expect(303)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_request'))
        .expect(auth.validateErrorDescription('requested response_mode not allowed for the requested response_type in FAPI 1.0 ID2'));
    });
  });

  describe('Request Object', () => {
    beforeEach(function () { return this.login(); });
    afterEach(function () { return this.logout(); });

    it('still works', async function () {
      const request = await new SignJWT({
        client_id: 'client',
        iss: 'client',
        scope: 'openid',
        response_type: 'code id_token',
        nonce: 'foo',
        redirect_uri: 'https://client.example.com/cb',
        aud: this.provider.issuer,
        state: 'foo',
        exp: epochTime() + 60,
      }).setProtectedHeader({ alg: 'ES256' }).sign(keypair.privateKey);

      const auth = new this.AuthorizationRequest({
        request,
        scope: 'openid',
        client_id: 'client',
        response_type: 'code id_token',
        nonce: 'foo',
        state: 'foo',
      });

      return this.wrap({
        agent: this.agent,
        route: '/auth',
        verb: 'get',
        auth,
      })
        .expect(303)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['id_token', 'code', 'state']))
        .expect(auth.validateClientLocation);
    });

    it('requires exp to be provided in the Request Object', async function () {
      const request = await new SignJWT({
        client_id: 'client',
        scope: 'openid',
        response_type: 'code id_token',
        nonce: 'foo',
      }).setProtectedHeader({ alg: 'ES256' }).sign(keypair.privateKey);

      const auth = new this.AuthorizationRequest({
        request,
        scope: 'openid',
        client_id: 'client',
        response_type: 'code id_token',
        nonce: 'foo',
      });

      return this.wrap({
        agent: this.agent,
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
  });
});
