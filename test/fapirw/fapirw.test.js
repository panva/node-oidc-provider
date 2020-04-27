const bootstrap = require('../test_helper');
const base64url = require('../../lib/helpers/base64url');
const epochTime = require('../../lib/helpers/epoch_time');

describe('Financial-grade API - Part 2: Read and Write API Security Profile behaviours', () => {
  before(bootstrap(__dirname));

  describe('userinfo', () => {
    it('echoes back the x-fapi-interaction-id header', function () {
      return this.agent.get('/me')
        .set('X-FAPI-Interaction-Id', 'b2bef873-2fd8-4fcd-943b-caafcd0b1c3b')
        .expect('x-fapi-interaction-id', 'b2bef873-2fd8-4fcd-943b-caafcd0b1c3b');
    });

    it('does not allow query string bearer token', async function () {
      const at = await new this.provider.AccessToken({ clientId: 'client', accountId: 'account', scope: 'openid' }).save();
      await this.agent.get('/me')
        .query({ access_token: at })
        .expect(this.failWith(400, 'invalid_request', 'access tokens must not be provided via query parameter'));

      await this.agent.get('/me')
        .auth(at, { type: 'bearer' })
        .expect(200)
        .expect({ sub: 'account' });

      await this.agent.post('/me')
        .type('form')
        .send({ access_token: at })
        .expect(200)
        .expect({ sub: 'account' });
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
        nonce: 'foo', // TODO: see oidc_required.js
      });

      return this.wrap({
        agent: this.agent,
        route: '/auth',
        verb: 'get',
        auth,
      })
        .expect(302)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_request'))
        .expect(auth.validateErrorDescription('response_mode not allowed for this response_type in FAPI mode'));
    });

    it('requires jwt response mode to be used when id token is not issued by authorization endpoint (JAR)', function () {
      const request = `${base64url.encode(JSON.stringify({ alg: 'none' }))}.${base64url.encode(JSON.stringify({
        scope: 'openid',
        client_id: 'client',
        response_type: 'code',
        nonce: 'foo', // TODO: see oidc_required.js
        exp: epochTime() + 60,
      }))}.`;

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
        .expect(302)
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_request'))
        .expect(auth.validateErrorDescription('response_mode not allowed for this response_type in FAPI mode'));
    });
  });

  describe('Request Object', () => {
    beforeEach(function () { return this.login(); });
    afterEach(function () { return this.logout(); });

    it('still works', function () {
      const request = `${base64url.encode(JSON.stringify({ alg: 'none' }))}.${base64url.encode(JSON.stringify({
        client_id: 'client',
        scope: 'openid',
        response_type: 'code id_token',
        nonce: 'foo',
        redirect_uri: 'https://client.example.com/cb',
        state: 'foo',
        exp: epochTime() + 60,
      }))}.`;

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
        .expect(302)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['id_token', 'code', 'state']))
        .expect(auth.validateClientLocation);
    });

    it('requires exp to be provided in the Request Object', function () {
      const request = `${base64url.encode(JSON.stringify({ alg: 'none' }))}.${base64url.encode(JSON.stringify({
        client_id: 'client',
        scope: 'openid',
        response_type: 'code id_token',
        nonce: 'foo',
      }))}.`;

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
        .expect(302)
        .expect(auth.validateFragment)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_request_object'))
        .expect(auth.validateErrorDescription('Request Object is missing the "exp" claim'));
    });
  });
});
