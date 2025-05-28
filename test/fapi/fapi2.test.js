import * as crypto from 'node:crypto';

import { createSandbox } from 'sinon';
import { SignJWT } from 'jose';
import { expect } from 'chai';

import bootstrap from '../test_helper.js';
import epochTime from '../../lib/helpers/epoch_time.js';

import { keypair } from './fapi2.config.js';

const sinon = createSandbox();

describe('FAPI 2.0 Final behaviours', () => {
  before(bootstrap(import.meta.url, { config: 'fapi2' }));
  afterEach(sinon.restore);

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

  describe('FAPI 2.0 Final Mode Authorization Request', () => {
    beforeEach(function () { return this.login(); });
    afterEach(function () { return this.logout(); });

    it('requires PKCE to be used on the authorization endpoint', function () {
      const auth = new this.AuthorizationRequest({
        scope: 'openid',
        client_id: 'client',
        response_type: 'code',
        code_challenge_method: undefined,
        code_challenge: undefined,
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
        .expect(auth.validateErrorDescription('Authorization Server policy requires PKCE to be used for this request'));
    });

    it('requires pkjwt audience to be the issuer identifier', async function () {
      const spy = sinon.spy();
      this.provider.on('pushed_authorization_request.error', spy);

      await this.agent.post('/request')
        .send({
          scope: 'openid',
          client_id: 'client',
          response_type: 'code',
          client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
          client_assertion: await new SignJWT({
            jti: crypto.randomUUID(),
            sub: 'client',
            iss: 'client',
            aud: this.provider.issuer + this.suitePath('/token'),
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

      expect(spy.args[0][1].error_detail).to.eql('audience (aud) must equal the issuer identifier url');
    });
  });

  context('allowOmittingSingleRegisteredRedirectUri', () => {
    before(function () {
      this.orig = i(this.provider).configuration.allowOmittingSingleRegisteredRedirectUri;
      i(this.provider).configuration.allowOmittingSingleRegisteredRedirectUri = true;
    });
    after(function () {
      i(this.provider).configuration.allowOmittingSingleRegisteredRedirectUri = this.orig;
    });
    before(function () { return this.login(); });
    after(function () { return this.logout(); });

    it('is ignored when FAPI 2.0 is used', async function () {
      const emitSpy = sinon.spy();
      const renderSpy = sinon.spy(i(this.provider).configuration, 'renderError');
      this.provider.once('authorization.error', emitSpy);

      const auth = new this.AuthorizationRequest({
        scope: 'openid',
        client_id: 'client',
        response_type: 'code',
        code_challenge_method: undefined,
        code_challenge: undefined,
        redirect_uri: undefined,
      });

      return this.wrap({
        agent: this.agent,
        route: '/auth',
        verb: 'get',
        auth,
      })
        .expect(() => {
          renderSpy.restore();
        })
        .expect(400)
        .expect(() => {
          expect(emitSpy.calledOnce).to.be.true;
          expect(renderSpy.calledOnce).to.be.true;
          const renderArgs = renderSpy.args[0];
          expect(renderArgs[1]).to.have.property('error', 'invalid_request');
          expect(renderArgs[1]).to.have.property('error_description', "missing required parameter 'redirect_uri'");
        });
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
        response_type: 'code',
        redirect_uri: 'https://client.example.com/cb',
        aud: this.provider.issuer,
        exp: epochTime() + 60,
        nbf: epochTime(),
        code_challenge_method: 'S256',
        code_challenge: crypto.hash('sha256', 'foo', 'base64url'),
      }).setProtectedHeader({ alg: 'ES256' }).sign(keypair.privateKey);

      const auth = new this.AuthorizationRequest({
        request,
        scope: 'openid',
        client_id: 'client',
        response_type: 'code',
      });

      return this.wrap({
        agent: this.agent,
        route: '/auth',
        verb: 'get',
        auth,
      })
        .expect(303)
        .expect(auth.validatePresence(['code']))
        .expect(auth.validateClientLocation);
    });

    it('requires exp to be provided in the Request Object', async function () {
      const request = await new SignJWT({
        aud: this.provider.issuer,
        code_challenge_method: 'S256',
        code_challenge: crypto.hash('sha256', 'foo', 'base64url'),
        // exp: epochTime() + 60,
        nbf: epochTime(),
        iss: 'client',
        client_id: 'client',
        scope: 'openid',
        response_type: 'code',
      }).setProtectedHeader({ alg: 'ES256' }).sign(keypair.privateKey);

      const auth = new this.AuthorizationRequest({
        request,
        scope: 'openid',
        client_id: 'client',
        response_type: 'code',
      });

      return this.wrap({
        agent: this.agent,
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

    it('requires nbf to be provided in the Request Object', async function () {
      const request = await new SignJWT({
        aud: this.provider.issuer,
        code_challenge_method: 'S256',
        code_challenge: crypto.hash('sha256', 'foo', 'base64url'),
        exp: epochTime() + 60,
        // nbf: epochTime(),
        client_id: 'client',
        scope: 'openid',
        iss: 'client',
        response_type: 'code',
      }).setProtectedHeader({ alg: 'ES256' }).sign(keypair.privateKey);

      const auth = new this.AuthorizationRequest({
        request,
        scope: 'openid',
        client_id: 'client',
        response_type: 'code',
      });

      return this.wrap({
        agent: this.agent,
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

    it('requires nbf to be no more than 3600 from exp', async function () {
      const request = await new SignJWT({
        exp: epochTime() + 60,
        nbf: epochTime() - 3600,
        aud: this.provider.issuer,
        code_challenge_method: 'S256',
        code_challenge: crypto.hash('sha256', 'foo', 'base64url'),
        client_id: 'client',
        scope: 'openid',
        iss: 'client',
        response_type: 'code',
      }).setProtectedHeader({ alg: 'ES256' }).sign(keypair.privateKey);

      const auth = new this.AuthorizationRequest({
        request,
        scope: 'openid',
        client_id: 'client',
        response_type: 'code',
      });

      return this.wrap({
        agent: this.agent,
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
