import { SignJWT } from 'jose';

import bootstrap from '../test_helper.js';
import epochTime from '../../lib/helpers/epoch_time.js';

import { keypair } from './fapi-final.config.js';

describe('Financial-grade API Security Profile 1.0 - Part 2: Advanced (FINAL) behaviours', () => {
  before(bootstrap(import.meta.url, { config: 'fapi-final' }));

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
        .expect(auth.validateErrorDescription('requested response_mode not allowed for the requested response_type in FAPI 1.0 Final'));
    });

    it('requires jwt response mode to be used when id token is not issued by authorization endpoint (JAR)', async function () {
      const request = await new SignJWT({
        scope: 'openid',
        client_id: 'client',
        response_type: 'code',
        nonce: 'foo',
        aud: this.provider.issuer,
        exp: epochTime() + 60,
        nbf: epochTime(),
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
        .expect(auth.validateErrorDescription('requested response_mode not allowed for the requested response_type in FAPI 1.0 Final'));
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
        nbf: epochTime(),
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
        aud: this.provider.issuer,
        // exp: epochTime() + 60,
        nbf: epochTime(),
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

    it('requires nbf to be provided in the Request Object', async function () {
      const request = await new SignJWT({
        aud: this.provider.issuer,
        exp: epochTime() + 60,
        // nbf: epochTime(),
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
        .expect(auth.validateErrorDescription("Request Object is missing the 'nbf' claim"));
    });

    it('requires nbf to be no more than 3600 from exp', async function () {
      const request = await new SignJWT({
        exp: epochTime() + 60,
        nbf: epochTime() - 3600,
        aud: this.provider.issuer,
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
        .expect(auth.validateErrorDescription("Request Object 'exp' claim too far from 'nbf' claim"));
    });
  });
});
