const { readFileSync } = require('fs');
const url = require('url');

const sinon = require('sinon');
const { expect } = require('chai');

const bootstrap = require('../test_helper');

const crt = readFileSync('./test/jwks/client.crt').toString();
const expectedS256 = 'A4DtL2JmUMhAsvJj5tKyn64SqzmuXbMrJa0n761y5v0';

describe('features.mTLS.certificateBoundAccessTokens', () => {
  before(bootstrap(__dirname));
  before(function () { return this.login(); });
  after(function () { return this.logout(); });

  describe('discovery', () => {
    it('extends discovery', function () {
      return this.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect((response) => {
          expect(response.body).to.have.property('tls_client_certificate_bound_access_tokens', true);
        });
    });
  });

  describe('userinfo', () => {
    it('acts like an RS checking the thumbprint now', async function () {
      const at = new this.provider.AccessToken({
        grantId: this.getGrantId('client'),
        accountId: this.loggedInAccountId,
        client: await this.provider.Client.find('client'),
        scope: 'openid',
      });
      at.setThumbprint('x5t', crt);

      const bearer = await at.save();

      await this.agent.get('/me')
        .auth(bearer, { type: 'bearer' })
        .expect(401);

      await this.agent.get('/me')
        .auth(bearer, { type: 'bearer' })
        .set('x-ssl-client-cert', 'foobar')
        .expect(401);

      await this.agent.get('/me')
        .auth(bearer, { type: 'bearer' })
        .set('x-ssl-client-cert', crt.replace(RegExp('\\r?\\n', 'g'), ''))
        .expect(200);
    });
  });

  describe('introspection', () => {
    it('exposes cnf now', async function () {
      const at = new this.provider.AccessToken({
        grantId: this.getGrantId('client'),
        accountId: this.loggedInAccountId,
        client: await this.provider.Client.find('client'),
        scope: 'openid',
      });
      at.setThumbprint('x5t', crt);

      const token = await at.save();

      await this.agent.post('/token/introspection')
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(200)
        .expect(({ body }) => {
          expect(body).to.have.property('cnf');
          expect(body).to.have.property('token_type', 'Bearer');
          expect(body.cnf).to.have.property('x5t#S256');
        });
    });
  });

  describe('urn:ietf:params:oauth:grant-type:device_code', () => {
    before(function () { return this.login({ scope: 'openid offline_access' }); });
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
        grantId: this.getGrantId('client'),
        scope: 'openid offline_access',
        accountId: this.loggedInAccountId,
      });
    });

    it('binds the access token to the certificate', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.success', spy);

      await this.agent.post('/token')
        .auth('client', 'secret')
        .send({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: this.dc,
        })
        .type('form')
        .set('x-ssl-client-cert', crt.replace(RegExp('\\r?\\n', 'g'), ''))
        .expect(200);

      expect(spy).to.have.property('calledOnce', true);
      const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
      expect(AccessToken).to.have.property('x5t#S256', expectedS256);
      expect(RefreshToken).not.to.have.property('x5t#S256');
    });

    it('verifies the request made with mutual-TLS', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);

      await this.agent.post('/token')
        .auth('client', 'secret')
        .send({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: this.dc,
        })
        .type('form')
        .expect(400)
        .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

      expect(spy).to.have.property('calledOnce', true);
      expect(spy.args[0][1]).to.have.property('error_detail', 'mutual TLS client certificate not provided');
    });

    it('binds the refresh token to the certificate for public clients', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.success', spy);

      // changes the code to client-none and
      this.TestAdapter.for('DeviceCode').syncUpdate(this.getTokenJti(this.dc), {
        clientId: 'client-none',
        grantId: this.getGrantId('client-none'),
        accountId: this.loggedInAccountId,
      });

      await this.agent.post('/token')
        .send({
          client_id: 'client-none',
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: this.dc,
        })
        .type('form')
        .set('x-ssl-client-cert', crt.replace(RegExp('\\r?\\n', 'g'), ''))
        .expect(200);

      expect(spy).to.have.property('calledOnce', true);
      const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
      expect(AccessToken).to.have.property('x5t#S256', expectedS256);
      expect(RefreshToken).to.have.property('x5t#S256', expectedS256);
    });
  });

  describe('urn:openid:params:grant-type:ciba', () => {
    beforeEach(async function () {
      await this.agent.post('/backchannel')
        .auth('client', 'secret')
        .send({
          scope: 'openid offline_access',
          login_hint: 'accountId',
        })
        .type('form')
        .expect(200)
        .expect(({ body: { auth_req_id: reqId } }) => {
          this.reqId = reqId;
        });
    });

    it('binds the access token to the certificate', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.success', spy);

      await this.agent.post('/token')
        .auth('client', 'secret')
        .send({
          grant_type: 'urn:openid:params:grant-type:ciba',
          auth_req_id: this.reqId,
        })
        .type('form')
        .set('x-ssl-client-cert', crt.replace(RegExp('\\r?\\n', 'g'), ''))
        .expect(200);

      expect(spy).to.have.property('calledOnce', true);
      const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
      expect(AccessToken).to.have.property('x5t#S256', expectedS256);
      expect(RefreshToken).not.to.have.property('x5t#S256');
    });

    it('verifies the request made with mutual-TLS', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);

      await this.agent.post('/token')
        .auth('client', 'secret')
        .send({
          grant_type: 'urn:openid:params:grant-type:ciba',
          auth_req_id: this.reqId,
        })
        .type('form')
        .expect(400)
        .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

      expect(spy).to.have.property('calledOnce', true);
      expect(spy.args[0][1]).to.have.property('error_detail', 'mutual TLS client certificate not provided');
    });

    it('binds the refresh token to the certificate for public clients', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.success', spy);

      // changes the code to client-none
      this.TestAdapter.for('BackchannelAuthenticationRequest').syncUpdate(this.getTokenJti(this.reqId), {
        clientId: 'client-none',
      });
      const { grantId } = this.TestAdapter.for('BackchannelAuthenticationRequest').syncFind(this.getTokenJti(this.reqId));
      this.TestAdapter.for('Grant').syncUpdate(grantId, {
        clientId: 'client-none',
      });

      await this.agent.post('/token')
        .send({
          client_id: 'client-none',
          grant_type: 'urn:openid:params:grant-type:ciba',
          auth_req_id: this.reqId,
        })
        .type('form')
        .set('x-ssl-client-cert', crt.replace(RegExp('\\r?\\n', 'g'), ''))
        .expect(200);

      expect(spy).to.have.property('calledOnce', true);
      const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
      expect(AccessToken).to.have.property('x5t#S256', expectedS256);
      expect(RefreshToken).to.have.property('x5t#S256', expectedS256);
    });
  });

  describe('authorization flow', () => {
    before(function () { return this.login({ scope: 'openid offline_access' }); });
    bootstrap.skipConsent();

    beforeEach(async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid offline_access',
        prompt: 'consent',
      });

      await this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validateClientLocation)
        .expect(({ headers: { location } }) => {
          const { query: { code } } = url.parse(location, true);
          this.code = code;
        });
    });

    describe('authorization_code', () => {
      it('binds the access token to the certificate', async function () {
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
          .set('x-ssl-client-cert', crt.replace(RegExp('\\r?\\n', 'g'), ''))
          .expect(200);

        expect(spy).to.have.property('calledOnce', true);
        const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
        expect(AccessToken).to.have.property('x5t#S256', expectedS256);
        expect(RefreshToken).not.to.have.property('x5t#S256');
      });

      it('verifies the request made with mutual-TLS', async function () {
        const spy = sinon.spy();
        this.provider.once('grant.error', spy);

        await this.agent.post('/token')
          .auth('client', 'secret')
          .send({
            grant_type: 'authorization_code',
            code: this.code,
            redirect_uri: 'https://client.example.com/cb',
          })
          .type('form')
          .expect(400)
          .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

        expect(spy).to.have.property('calledOnce', true);
        expect(spy.args[0][1]).to.have.property('error_detail', 'mutual TLS client certificate not provided');
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
          .set('x-ssl-client-cert', crt.replace(RegExp('\\r?\\n', 'g'), ''))
          .expect(({ body }) => {
            this.rt = body.refresh_token;
          });
      });

      it('binds the access token to the certificate', async function () {
        const spy = sinon.spy();
        this.provider.once('grant.success', spy);

        await this.agent.post('/token')
          .auth('client', 'secret')
          .send({
            grant_type: 'refresh_token',
            refresh_token: this.rt,
          })
          .type('form')
          .set('x-ssl-client-cert', crt.replace(RegExp('\\r?\\n', 'g'), ''))
          .expect(200);

        expect(spy).to.have.property('calledOnce', true);
        const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
        expect(AccessToken).to.have.property('x5t#S256', expectedS256);
        expect(RefreshToken['x5t#S256']).to.be.undefined;
      });

      it('verifies the request made with mutual-TLS', async function () {
        const spy = sinon.spy();
        this.provider.once('grant.error', spy);

        await this.agent.post('/token')
          .auth('client', 'secret')
          .send({
            grant_type: 'refresh_token',
            refresh_token: this.rt,
          })
          .type('form')
          .expect(400)
          .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

        expect(spy).to.have.property('calledOnce', true);
        expect(spy.args[0][1]).to.have.property('error_detail', 'mutual TLS client certificate not provided');
      });
    });
  });

  describe('authorization flow (public client)', () => {
    before(function () { return this.login({ scope: 'openid offline_access' }); });
    bootstrap.skipConsent();

    beforeEach(async function () {
      const auth = new this.AuthorizationRequest({
        client_id: 'client-none',
        response_type: 'code',
        scope: 'openid offline_access',
        prompt: 'consent',
      });

      await this.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validateClientLocation)
        .expect(({ headers: { location } }) => {
          const { query: { code } } = url.parse(location, true);
          this.code = code;
        });
    });

    describe('authorization_code', () => {
      it('binds the access token to the certificate', async function () {
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
          .set('x-ssl-client-cert', crt.replace(RegExp('\\r?\\n', 'g'), ''))
          .expect(200);

        expect(spy).to.have.property('calledOnce', true);
        const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
        expect(AccessToken).to.have.property('x5t#S256', expectedS256);
        expect(RefreshToken).to.have.property('x5t#S256', expectedS256);
      });

      it('verifies the request made with mutual-TLS', async function () {
        const spy = sinon.spy();
        this.provider.once('grant.error', spy);

        await this.agent.post('/token')
          .send({
            client_id: 'client-none',
            grant_type: 'authorization_code',
            code: this.code,
            redirect_uri: 'https://client.example.com/cb',
          })
          .type('form')
          .expect(400)
          .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

        expect(spy).to.have.property('calledOnce', true);
        expect(spy.args[0][1]).to.have.property('error_detail', 'mutual TLS client certificate not provided');
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
          .set('x-ssl-client-cert', crt.replace(RegExp('\\r?\\n', 'g'), ''))
          .expect(({ body }) => {
            this.rt = body.refresh_token;
          });
      });

      it('binds the access token to the certificate', async function () {
        const spy = sinon.spy();
        this.provider.once('grant.success', spy);

        await this.agent.post('/token')
          .send({
            client_id: 'client-none',
            grant_type: 'refresh_token',
            refresh_token: this.rt,
          })
          .type('form')
          .set('x-ssl-client-cert', crt.replace(RegExp('\\r?\\n', 'g'), ''))
          .expect(200);

        expect(spy).to.have.property('calledOnce', true);
        const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
        expect(AccessToken).to.have.property('x5t#S256', expectedS256);
        expect(RefreshToken).to.have.property('x5t#S256', expectedS256);
      });

      it('verifies the request made with mutual-TLS', async function () {
        const spy = sinon.spy();
        this.provider.once('grant.error', spy);

        await this.agent.post('/token')
          .send({
            client_id: 'client-none',
            grant_type: 'refresh_token',
            refresh_token: this.rt,
          })
          .type('form')
          .expect(400)
          .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

        expect(spy).to.have.property('calledOnce', true);
        expect(spy.args[0][1]).to.have.property('error_detail', 'mutual TLS client certificate not provided');
      });

      it('verifies the request made with mutual-TLS using the same cert', async function () {
        const spy = sinon.spy();
        this.provider.once('grant.error', spy);

        await this.agent.post('/token')
          .send({
            client_id: 'client-none',
            grant_type: 'refresh_token',
            refresh_token: this.rt,
          })
          .set('x-ssl-client-cert', 'foo')
          .type('form')
          .expect(400)
          .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

        expect(spy).to.have.property('calledOnce', true);
        expect(spy.args[0][1]).to.have.property('error_detail', 'failed x5t#S256 verification');
      });
    });
  });

  describe('client_credentials', () => {
    it('binds the access token to the certificate', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.success', spy);

      await this.agent.post('/token')
        .auth('client', 'secret')
        .send({ grant_type: 'client_credentials' })
        .set('x-ssl-client-cert', crt.replace(RegExp('\\r?\\n', 'g'), ''))
        .type('form')
        .expect(200);

      expect(spy).to.have.property('calledOnce', true);
      const { oidc: { entities: { ClientCredentials } } } = spy.args[0][0];
      expect(ClientCredentials).to.have.property('x5t#S256', expectedS256);
    });

    it('verifies the request was made with mutual-TLS', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);

      await this.agent.post('/token')
        .auth('client', 'secret')
        .send({ grant_type: 'client_credentials' })
        .type('form')
        .expect(400)
        .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

      expect(spy).to.have.property('calledOnce', true);
      expect(spy.args[0][1]).to.have.property('error_detail', 'mutual TLS client certificate not provided');
    });
  });
});
