import { describe, before, afterEach, it, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';

import { createSandbox } from 'sinon';
import { SignJWT } from 'jose';

import bootstrap from '../test_helper.js';
import epochTime from '../../lib/helpers/epoch_time.js';

import { keypair } from './fapi2.config.js';

const sinon = createSandbox();

describe('FAPI 2.0 Final behaviours', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture, { config: 'fapi2' }), { timeout: 3000 });
  afterEach(() => sinon.restore(), { timeout: 3000 });

  describe('userinfo', () => {
    const fixture1 = Object.create(fixture);

    before(() => fixture1.login(), { timeout: 3000 });

    it('does not allow query string bearer token', { timeout: 3000 }, async () => {
      const at = await new fixture1.provider.AccessToken({
        client: await fixture1.provider.Client.find('client'),
        accountId: fixture1.loggedInAccountId,
        grantId: fixture1.getGrantId(),
        scope: 'openid',
      }).save();

      await fixture1.agent.get('/me')
        .query({ access_token: at })
        .expect(fixture1.failWith(400, 'invalid_request', 'access tokens must not be provided via query parameter'));

      await fixture1.agent.get('/me')
        .auth(at, { type: 'bearer' })
        .expect(200)
        .expect({ sub: fixture1.loggedInAccountId });

      await fixture1.agent.post('/me')
        .type('form')
        .send({ access_token: at })
        .expect(200)
        .expect({ sub: fixture1.loggedInAccountId });
    });
  });

  describe('FAPI 2.0 Final Mode Authorization Request', () => {
    const fixture2 = Object.create(fixture);

    beforeEach(() => fixture2.login(), { timeout: 3000 });
    afterEach(() => fixture2.logout(), { timeout: 3000 });

    it('requires PKCE to be used on the authorization endpoint', { timeout: 3000 }, () => {
      const auth = new fixture2.AuthorizationRequest({
        scope: 'openid',
        client_id: 'client',
        response_type: 'code',
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
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_request'))
        .expect(auth.validateErrorDescription('Authorization Server policy requires PKCE to be used for this request'));
    });

    it('requires pkjwt audience to be the issuer identifier', { timeout: 3000 }, async () => {
      const spy = sinon.spy();
      fixture2.provider.on('pushed_authorization_request.error', spy);

      await fixture2.agent.post('/request')
        .send({
          scope: 'openid',
          client_id: 'client',
          response_type: 'code',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: await new SignJWT({
            jti: crypto.randomUUID(),
            sub: 'client',
            iss: 'client',
            aud: fixture2.provider.issuer + fixture2.suitePath('/token'),
            exp: epochTime() + 60,
            nbf: epochTime(),
          }).setProtectedHeader({ alg: 'ES256' }).sign(keypair.privateKey),
          code_challenge_method: 'S256',
          code_challenge: crypto.hash('sha256', 'foo', 'base64url'),
        })
        .type('form')
        .expect(401)
        .expect({
          error: 'invalid_client',
          error_description: 'client authentication failed',
        });

      assert.deepEqual(spy.args[0][1].error_detail, 'audience (aud) must equal the issuer identifier url');
    });
  });

  describe('allowOmittingSingleRegisteredRedirectUri', () => {
    const fixture3 = Object.create(fixture);

    before(() => {
      fixture3.orig = i(fixture3.provider).configuration.allowOmittingSingleRegisteredRedirectUri;
      i(fixture3.provider).configuration.allowOmittingSingleRegisteredRedirectUri = true;
    }, { timeout: 3000 });
    after(() => {
      i(fixture3.provider).configuration.allowOmittingSingleRegisteredRedirectUri = fixture3.orig;
    }, { timeout: 3000 });
    before(() => fixture3.login(), { timeout: 3000 });
    after(() => fixture3.logout(), { timeout: 3000 });

    it('is ignored when FAPI 2.0 is used', { timeout: 3000 }, async () => {
      const emitSpy = sinon.spy();
      const renderSpy = sinon.spy(i(fixture3.provider).configuration, 'renderError');
      fixture3.provider.once('authorization.error', emitSpy);

      const auth = new fixture3.AuthorizationRequest({
        scope: 'openid',
        client_id: 'client',
        response_type: 'code',
        code_challenge_method: undefined,
        code_challenge: undefined,
        redirect_uri: undefined,
      });

      return fixture3.wrap({
        agent: fixture3.agent,
        route: '/auth',
        verb: 'get',
        auth,
      })
        .expect(() => {
          renderSpy.restore();
        })
        .expect(400)
        .expect(() => {
          assert.equal(emitSpy.calledOnce, true);
          assert.equal(renderSpy.calledOnce, true);
          const renderArgs = renderSpy.args[0];
          ((actual) => { assert.ok('error' in Object(actual)); assert.equal(actual.error, 'invalid_request'); })(renderArgs[1]);
          ((actual) => { assert.ok('error_description' in Object(actual)); assert.equal(actual.error_description, "missing required parameter 'redirect_uri'"); })(renderArgs[1]);
        });
    });
  });

  describe('Request Object', () => {
    const fixture4 = Object.create(fixture);

    beforeEach(() => fixture4.login(), { timeout: 3000 });
    afterEach(() => fixture4.logout(), { timeout: 3000 });

    it('still works', { timeout: 3000 }, async () => {
      const request = await new SignJWT({
        client_id: 'client',
        iss: 'client',
        scope: 'openid',
        response_type: 'code',
        redirect_uri: 'https://client.example.com/cb',
        aud: fixture4.provider.issuer,
        exp: epochTime() + 60,
        nbf: epochTime(),
        code_challenge_method: 'S256',
        code_challenge: crypto.hash('sha256', 'foo', 'base64url'),
      }).setProtectedHeader({ alg: 'ES256' }).sign(keypair.privateKey);

      const auth = new fixture4.AuthorizationRequest({
        request,
        scope: 'openid',
        client_id: 'client',
        response_type: 'code',
      });

      return fixture4.wrap({
        agent: fixture4.agent,
        route: '/auth',
        verb: 'get',
        auth,
      })
        .expect(303)
        .expect(auth.validatePresence(['code']))
        .expect(auth.validateClientLocation);
    });

    it('requires exp to be provided in the Request Object', { timeout: 3000 }, async () => {
      const request = await new SignJWT({
        aud: fixture4.provider.issuer,
        code_challenge_method: 'S256',
        code_challenge: crypto.hash('sha256', 'foo', 'base64url'),
        // exp: epochTime() + 60,
        nbf: epochTime(),
        iss: 'client',
        client_id: 'client',
        scope: 'openid',
        response_type: 'code',
      }).setProtectedHeader({ alg: 'ES256' }).sign(keypair.privateKey);

      const auth = new fixture4.AuthorizationRequest({
        request,
        scope: 'openid',
        client_id: 'client',
        response_type: 'code',
      });

      return fixture4.wrap({
        agent: fixture4.agent,
        route: '/auth',
        verb: 'get',
        auth,
      })
        .expect(303)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_request_object'))
        .expect(auth.validateErrorDescription("Request Object is missing the 'exp' claim"));
    });

    it('requires nbf to be provided in the Request Object', { timeout: 3000 }, async () => {
      const request = await new SignJWT({
        aud: fixture4.provider.issuer,
        code_challenge_method: 'S256',
        code_challenge: crypto.hash('sha256', 'foo', 'base64url'),
        exp: epochTime() + 60,
        // nbf: epochTime(),
        client_id: 'client',
        scope: 'openid',
        iss: 'client',
        response_type: 'code',
      }).setProtectedHeader({ alg: 'ES256' }).sign(keypair.privateKey);

      const auth = new fixture4.AuthorizationRequest({
        request,
        scope: 'openid',
        client_id: 'client',
        response_type: 'code',
      });

      return fixture4.wrap({
        agent: fixture4.agent,
        route: '/auth',
        verb: 'get',
        auth,
      })
        .expect(303)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_request_object'))
        .expect(auth.validateErrorDescription("Request Object is missing the 'nbf' claim"));
    });

    it('requires nbf to be no more than 3600 from exp', { timeout: 3000 }, async () => {
      const request = await new SignJWT({
        exp: epochTime() + 60,
        nbf: epochTime() - 3600,
        aud: fixture4.provider.issuer,
        code_challenge_method: 'S256',
        code_challenge: crypto.hash('sha256', 'foo', 'base64url'),
        client_id: 'client',
        scope: 'openid',
        iss: 'client',
        response_type: 'code',
      }).setProtectedHeader({ alg: 'ES256' }).sign(keypair.privateKey);

      const auth = new fixture4.AuthorizationRequest({
        request,
        scope: 'openid',
        client_id: 'client',
        response_type: 'code',
      });

      return fixture4.wrap({
        agent: fixture4.agent,
        route: '/auth',
        verb: 'get',
        auth,
      })
        .expect(303)
        .expect(auth.validatePresence(['error', 'error_description', 'state']))
        .expect(auth.validateClientLocation)
        .expect(auth.validateError('invalid_request_object'))
        .expect(auth.validateErrorDescription("Request Object 'exp' claim too far from 'nbf' claim"));
    });
  });
});
