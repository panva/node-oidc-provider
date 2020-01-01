const url = require('url');

const sinon = require('sinon');
const { expect } = require('chai');
const { JWK, JWT } = require('jose');

const nanoid = require('../../lib/helpers/nanoid');
const epochTime = require('../../lib/helpers/epoch_time');
const bootstrap = require('../test_helper');
const base64url = require('../../lib/helpers/base64url');

const expectedS256 = 'ZjEgWN6HnCZRssL1jRQHiJi6vlWXolM5Zba8FQBYONg';

describe('features.dPoP', () => {
  before(bootstrap(__dirname));
  before(async function () {
    this.jwk = JWK.asKey({
      crv: 'P-256',
      x: '1_Dz3o3_V5CpuzQ78gImNb2QIKjBfREXwBQxjyO0xig',
      y: 'YMSWnnBjNeMvfL9nZtYSyxGKZtPFG28jJwjjk06716o',
      d: 'IHFCcQXeUew9o_7jAIj2t6GEoJpgrOC9L_pQGlvRpto',
      kty: 'EC',
    });
  });
  before(function () {
    this.proof = (uri, method, jwk = this.jwk) => JWT.sign({ htu: uri, htm: method, jti: nanoid() }, jwk, { kid: false, header: { typ: 'dpop+jwt', jwk: JWK.asKey(jwk) } });
  });

  it('validates the way DPoP Proof JWT is provided', async function () {
    const at = new this.provider.AccessToken({
      accountId: 'account',
      clientId: 'client',
      scope: 'openid',
    });
    at.setThumbprint('jkt', this.jwk);

    const dpop = await at.save();

    await this.agent.get('/me')
      .set('Authorization', `DPoP ${dpop}`)
      .expect(400)
      .expect({ error: 'invalid_request', error_description: '`DPoP` header not provided' });

    await this.agent.post('/me')
      .set('DPoP', this.proof(`${this.provider.issuer}${this.suitePath('/me')}`, 'POST'))
      .send({ access_token: dpop })
      .type('form')
      .expect(400)
      .expect({ error: 'invalid_request', error_description: '`DPoP` tokens must be provided via an authorization header' });

    await this.agent.get('/me')
      .set('DPoP', this.proof(`${this.provider.issuer}${this.suitePath('/me')}`, 'GET'))
      .set('Authorization', `Bearer ${dpop}`)
      .expect(400)
      .expect({ error: 'invalid_request', error_description: 'authorization header scheme must be `DPoP` when DPoP is used' });
  });

  it('validates the DPoP Proof JWT is conform', async function () {
    const key = await JWK.generate('EC');

    for (const value of [undefined, '', 1, true, null]) { // eslint-disable-line no-restricted-syntax
      await this.agent.get('/me') // eslint-disable-line no-await-in-loop
        .set('DPoP', JWT.sign({}, key, { kid: false, header: { typ: value } }))
        .set('Authorization', 'DPoP foo')
        .expect(400)
        .expect({ error: 'invalid_request', error_description: 'invalid DPoP Proof JWT (typ must be dpop+jwt)' });
    }

    for (const value of [undefined, '', 1, true, null, 'none', 'HS256']) { // eslint-disable-line no-restricted-syntax
      await this.agent.get('/me') // eslint-disable-line no-await-in-loop
        .set('DPoP', `${base64url.encode(JSON.stringify({ typ: 'dpop+jwt', alg: value }))}.e30.`)
        .set('Authorization', 'DPoP foo')
        .expect(400)
        .expect({ error: 'invalid_request', error_description: 'invalid DPoP Proof JWT (invalid alg)' });
    }

    await this.agent.get('/me') // eslint-disable-line no-await-in-loop
      .set('DPoP', `${base64url.encode(JSON.stringify({ typ: 'dpop+jwt', alg: 'Unsupported' }))}.e30.`)
      .set('Authorization', 'DPoP foo')
      .expect(400)
      .expect({ error: 'invalid_request', error_description: 'invalid DPoP Proof JWT (unsupported alg)' });

    for (const value of [undefined, '', 1, true, null, 'foo']) { // eslint-disable-line no-restricted-syntax
      await this.agent.get('/me') // eslint-disable-line no-await-in-loop
        .set('DPoP', JWT.sign({}, key, { kid: false, header: { typ: 'dpop+jwt', jwk: value } }))
        .set('Authorization', 'DPoP foo')
        .expect(400)
        .expect({ error: 'invalid_request', error_description: 'invalid DPoP Proof JWT (header must have a jwk)' });
    }

    for (const value of [[], {}, { kty: 'foo' }]) { // eslint-disable-line no-restricted-syntax
      await this.agent.get('/me') // eslint-disable-line no-await-in-loop
        .set('DPoP', JWT.sign({}, key, { kid: false, header: { typ: 'dpop+jwt', jwk: value } }))
        .set('Authorization', 'DPoP foo')
        .expect(400)
        .expect({ error: 'invalid_request', error_description: 'invalid DPoP Proof JWT (failed to import jwk)' });
    }

    await this.agent.get('/me') // eslint-disable-line no-await-in-loop
      .set('DPoP', JWT.sign({}, key, { kid: false, header: { typ: 'dpop+jwt', jwk: key.toJWK(true) } }))
      .set('Authorization', 'DPoP foo')
      .expect(400)
      .expect({ error: 'invalid_request', error_description: 'invalid DPoP Proof JWT (jwk must be a public key)' });

    await this.agent.get('/me') // eslint-disable-line no-await-in-loop
      .set('DPoP', JWT.sign({}, key, { kid: false, header: { typ: 'dpop+jwt', jwk: await JWK.generate('oct') } }))
      .set('Authorization', 'DPoP foo')
      .expect(400)
      .expect({ error: 'invalid_request', error_description: 'invalid DPoP Proof JWT (jwk must be a public key)' });

    for (const value of [[], {}, 1, null, '', false, true]) { // eslint-disable-line no-restricted-syntax
      await this.agent.get('/me') // eslint-disable-line no-await-in-loop
        .set('DPoP', JWT.sign({ jti: value }, key, { kid: false, header: { typ: 'dpop+jwt', jwk: key } }))
        .set('Authorization', 'DPoP foo')
        .expect(400)
        .expect({ error: 'invalid_request', error_description: 'invalid DPoP Proof JWT (must have a jti string property)' });
    }

    for (const value of [[], {}, 0, null, '', false, true]) { // eslint-disable-line no-restricted-syntax
      await this.agent.get('/me') // eslint-disable-line no-await-in-loop
        .set('DPoP', JWT.sign({ jti: 'foo', iat: value }, key, { kid: false, iat: false, header: { typ: 'dpop+jwt', jwk: key } }))
        .set('Authorization', 'DPoP foo')
        .expect(400)
        .expect({ error: 'invalid_request', error_description: 'invalid DPoP Proof JWT (must have a iat number property)' });
    }

    await this.agent.get('/me') // eslint-disable-line no-await-in-loop
      .set('DPoP', JWT.sign({ jti: 'foo', htm: 'POST' }, key, { kid: false, header: { typ: 'dpop+jwt', jwk: key } }))
      .set('Authorization', 'DPoP foo')
      .expect(400)
      .expect({ error: 'invalid_request', error_description: 'invalid DPoP Proof JWT (htm mismatch)' });

    await this.agent.get('/me') // eslint-disable-line no-await-in-loop
      .set('DPoP', JWT.sign({ jti: 'foo', htm: 'GET', htu: 'foo' }, key, { kid: false, header: { typ: 'dpop+jwt', jwk: key } }))
      .set('Authorization', 'DPoP foo')
      .expect(400)
      .expect({ error: 'invalid_request', error_description: 'invalid DPoP Proof JWT (htu mismatch)' });

    await this.agent.get('/me') // eslint-disable-line no-await-in-loop
      .set('DPoP', JWT.sign({
        jti: 'foo', htm: 'GET', htu: `${this.provider.issuer}${this.suitePath('/me')}`, iat: epochTime() - 61,
      }, key, { kid: false, iat: false, header: { typ: 'dpop+jwt', jwk: key } }))
      .set('Authorization', 'DPoP foo')
      .expect(400)
      .expect({ error: 'invalid_request', error_description: 'invalid DPoP Proof JWT (failed claim check ("iat" claim timestamp check failed (too far in the past)))' });

    await this.agent.get('/me') // eslint-disable-line no-await-in-loop
      .set('DPoP', JWT.sign({
        jti: 'foo', htm: 'GET', htu: `${this.provider.issuer}${this.suitePath('/me')}`,
      }, key, { kid: false, header: { typ: 'dpop+jwt', jwk: await JWK.generate('EC') } }))
      .set('Authorization', 'DPoP foo')
      .expect(400)
      .expect({ error: 'invalid_request', error_description: 'invalid DPoP Proof JWT (signature verification failed)' });
  });

  describe('userinfo', () => {
    it('acts like an RS checking the DPoP Proof and thumbprint now', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'account',
        clientId: 'client',
        scope: 'openid',
      });
      at.setThumbprint('jkt', this.jwk);

      const dpop = await at.save();
      const proof = this.proof(`${this.provider.issuer}${this.suitePath('/me')}`, 'GET');

      await this.agent.get('/me')
        .set('Authorization', `DPoP ${dpop}`)
        .set('DPoP', proof)
        .expect(200);

      let spy = sinon.spy();
      this.provider.once('userinfo.error', spy);

      await this.agent.get('/me')
        .set('Authorization', `DPoP ${dpop}`)
        .set('DPoP', proof)
        .expect(401)
        .expect({ error: 'invalid_token', error_description: 'invalid token provided' });

      expect(spy).to.have.property('calledOnce', true);
      expect(spy.args[0][1]).to.have.property('error_detail', 'DPoP Token Replay detected');

      const anotherJWK = JWK.generateSync('EC');

      spy = sinon.spy();
      this.provider.once('userinfo.error', spy);

      await this.agent.get('/me')
        .set('Authorization', `DPoP ${dpop}`)
        .set('DPoP', this.proof(`${this.provider.issuer}${this.suitePath('/me')}`, 'GET', anotherJWK))
        .expect({ error: 'invalid_token', error_description: 'invalid token provided' })
        .expect(401);

      expect(spy).to.have.property('calledOnce', true);
      expect(spy.args[0][1]).to.have.property('error_detail', 'failed jkt verification');

      spy = sinon.spy();
      this.provider.once('userinfo.error', spy);

      await this.agent.get('/me')
        .set('Authorization', `Bearer ${dpop}`)
        .expect({ error: 'invalid_token', error_description: 'invalid token provided' })
        .expect(401);

      expect(spy).to.have.property('calledOnce', true);
      expect(spy.args[0][1]).to.have.property('error_detail', 'failed jkt verification');
    });
  });

  describe('introspection', () => {
    it('exposes cnf and DPoP token type now', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'account',
        clientId: 'client',
        scope: 'openid',
      });
      at.setThumbprint('jkt', this.jwk);

      const token = await at.save();

      await this.agent.post('/token/introspection')
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(200)
        .expect(({ body }) => {
          expect(body).to.have.property('cnf');
          expect(body).to.have.property('token_type', 'DPoP');
          expect(body.cnf).to.have.property('jkt');
        });
    });
  });

  describe('urn:ietf:params:oauth:grant-type:device_code', () => {
    beforeEach(async function () {
      await this.agent.post('/device/auth')
        .auth('client', 'secret')
        .send({ scope: 'openid' })
        .type('form')
        .expect(200)
        .expect(({ body: { device_code: dc } }) => {
          this.dc = dc;
        });

      this.TestAdapter.for('DeviceCode').syncUpdate(this.getTokenJti(this.dc), {
        scope: 'openid offline_access',
        accountId: 'account',
      });
    });

    it('binds the access token to the jwk', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.success', spy);

      await this.agent.post('/token')
        .auth('client', 'secret')
        .send({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: this.dc,
        })
        .type('form')
        .set('DPoP', this.proof(`${this.provider.issuer}${this.suitePath('/token')}`, 'POST'))
        .expect(200);

      expect(spy).to.have.property('calledOnce', true);
      const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
      expect(AccessToken).to.have.property('jkt', expectedS256);
      expect(RefreshToken).not.to.have.property('jkt');
    });

    it('binds the refresh token to the jwk for public clients', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.success', spy);

      // changes the code to client-none and
      this.TestAdapter.for('DeviceCode').syncUpdate(this.getTokenJti(this.dc), {
        clientId: 'client-none',
      });

      await this.agent.post('/token')
        .send({
          client_id: 'client-none',
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: this.dc,
        })
        .type('form')
        .set('DPoP', this.proof(`${this.provider.issuer}${this.suitePath('/token')}`, 'POST'))
        .expect(200);

      expect(spy).to.have.property('calledOnce', true);
      const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
      expect(AccessToken).to.have.property('jkt', expectedS256);
      expect(RefreshToken).to.have.property('jkt', expectedS256);
    });
  });

  describe('authorization flow', () => {
    before(function () { return this.login(); });
    bootstrap.skipConsent();

    beforeEach(async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid offline_access',
        prompt: 'consent',
      });

      await this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(302)
        .expect(auth.validateClientLocation)
        .expect(({ headers: { location } }) => {
          const { query: { code } } = url.parse(location, true);
          this.code = code;
        });
    });

    describe('authorization_code', () => {
      it('binds the access token to the jwk', async function () {
        const spy = sinon.spy();
        this.provider.once('grant.success', spy);

        await this.agent.post('/token')
          .auth('client', 'secret')
          .send({
            grant_type: 'authorization_code',
            code: this.code,
            redirect_uri: 'https://client.example.com/cb',
          })
          .type('form')
          .set('DPoP', this.proof(`${this.provider.issuer}${this.suitePath('/token')}`, 'POST'))
          .expect(200);

        expect(spy).to.have.property('calledOnce', true);
        const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
        expect(AccessToken).to.have.property('jkt', expectedS256);
        expect(RefreshToken).not.to.have.property('jkt');
      });
    });

    describe('refresh_token', () => {
      beforeEach(async function () {
        await this.agent.post('/token')
          .auth('client', 'secret')
          .send({
            grant_type: 'authorization_code',
            code: this.code,
            redirect_uri: 'https://client.example.com/cb',
          })
          .type('form')
          .set('DPoP', this.proof(`${this.provider.issuer}${this.suitePath('/token')}`, 'POST'))
          .expect(({ body }) => {
            this.rt = body.refresh_token;
          });
      });

      it('binds the access token to the jwk', async function () {
        const spy = sinon.spy();
        this.provider.once('grant.success', spy);

        await this.agent.post('/token')
          .auth('client', 'secret')
          .send({
            grant_type: 'refresh_token',
            refresh_token: this.rt,
          })
          .type('form')
          .set('DPoP', this.proof(`${this.provider.issuer}${this.suitePath('/token')}`, 'POST'))
          .expect(200);

        expect(spy).to.have.property('calledOnce', true);
        const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
        expect(AccessToken).to.have.property('jkt', expectedS256);
        expect(RefreshToken.jkt).to.be.undefined;
      });
    });
  });

  describe('authorization flow (public client)', () => {
    before(function () { return this.login(); });
    bootstrap.skipConsent();

    beforeEach(async function () {
      const auth = new this.AuthorizationRequest({
        client_id: 'client-none',
        response_type: 'code',
        scope: 'openid offline_access',
        prompt: 'consent',
      });

      await this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(302)
        .expect(auth.validateClientLocation)
        .expect(({ headers: { location } }) => {
          const { query: { code } } = url.parse(location, true);
          this.code = code;
        });
    });

    describe('authorization_code', () => {
      it('binds the access token to the jwk', async function () {
        const spy = sinon.spy();
        this.provider.once('grant.success', spy);

        await this.agent.post('/token')
          .send({
            client_id: 'client-none',
            grant_type: 'authorization_code',
            code: this.code,
            redirect_uri: 'https://client.example.com/cb',
          })
          .type('form')
          .set('DPoP', this.proof(`${this.provider.issuer}${this.suitePath('/token')}`, 'POST'))
          .expect(200);

        expect(spy).to.have.property('calledOnce', true);
        const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
        expect(AccessToken).to.have.property('jkt', expectedS256);
        expect(RefreshToken).to.have.property('jkt', expectedS256);
      });
    });

    describe('refresh_token', () => {
      beforeEach(async function () {
        await this.agent.post('/token')
          .send({
            client_id: 'client-none',
            grant_type: 'authorization_code',
            code: this.code,
            redirect_uri: 'https://client.example.com/cb',
          })
          .type('form')
          .set('DPoP', this.proof(`${this.provider.issuer}${this.suitePath('/token')}`, 'POST'))
          .expect(({ body }) => {
            this.rt = body.refresh_token;
          });
      });

      it('binds the access token to the jwk', async function () {
        const spy = sinon.spy();
        this.provider.once('grant.success', spy);

        await this.agent.post('/token')
          .send({
            client_id: 'client-none',
            grant_type: 'refresh_token',
            refresh_token: this.rt,
          })
          .type('form')
          .set('DPoP', this.proof(`${this.provider.issuer}${this.suitePath('/token')}`, 'POST'))
          .expect(200);

        expect(spy).to.have.property('calledOnce', true);
        const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
        expect(AccessToken).to.have.property('jkt', expectedS256);
        expect(RefreshToken).to.have.property('jkt', expectedS256);
      });

      it('verifies the request made with the same cert jwk', async function () {
        const spy = sinon.spy();
        this.provider.once('grant.error', spy);

        const anotherJWK = JWK.generateSync('EC');
        await this.agent.post('/token')
          .send({
            client_id: 'client-none',
            grant_type: 'refresh_token',
            refresh_token: this.rt,
          })
          .set('DPoP', this.proof(`${this.provider.issuer}${this.suitePath('/token')}`, 'POST', anotherJWK))
          .type('form')
          .expect(400)
          .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

        expect(spy).to.have.property('calledOnce', true);
        expect(spy.args[0][1]).to.have.property('error_detail', 'failed jkt verification');
      });
    });
  });

  describe('client_credentials', () => {
    it('binds the access token to the jwk', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.success', spy);

      await this.agent.post('/token')
        .auth('client', 'secret')
        .send({ grant_type: 'client_credentials' })
        .set('DPoP', this.proof(`${this.provider.issuer}${this.suitePath('/token')}`, 'POST'))
        .type('form')
        .expect(200);

      expect(spy).to.have.property('calledOnce', true);
      const { oidc: { entities: { ClientCredentials } } } = spy.args[0][0];
      expect(ClientCredentials).to.have.property('jkt', expectedS256);
    });
  });
});
