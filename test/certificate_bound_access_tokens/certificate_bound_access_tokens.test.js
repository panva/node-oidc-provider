const { readFileSync } = require('fs');
const url = require('url');

const sinon = require('sinon');
const { expect } = require('chai');

const bootstrap = require('../test_helper');

const crt = readFileSync('./test/jwks/client.crt').toString();
const expectedS256 = 'eXvgMeO-8uLw0FGYkJefOXSFHOnbbcfv95rIYCPsbpo';

describe('features.certificateBoundAccessTokens', () => {
  before(bootstrap(__dirname));

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
        accountId: 'account',
        clientId: 'client',
        scope: 'openid',
      });
      at.setS256Thumbprint(crt);

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
        .set('x-ssl-client-cert', crt.replace(/\n/g, ''))
        .expect(200);
    });
  });

  describe('introspection', () => {
    it('exposes cnf now', async function () {
      const at = new this.provider.AccessToken({
        accountId: 'account',
        clientId: 'client',
        scope: 'openid',
      });
      at.setS256Thumbprint(crt);

      const token = await at.save();

      await this.agent.post('/token/introspection')
        .send({
          token,
          client_id: 'client',
        })
        .type('form')
        .expect(200)
        .expect(({ body }) => {
          expect(body).to.have.property('cnf');
          expect(body.cnf).to.have.property('x5t#S256');
        });
    });
  });

  describe('urn:ietf:params:oauth:grant-type:device_code', () => {
    beforeEach(async function () {
      await this.agent.post('/device/auth')
        .send({
          client_id: 'client',
          scope: 'openid',
        })
        .type('form')
        .expect(200)
        .expect(({ body: { device_code: dc } }) => {
          this.dc = dc;
        });

      this.TestAdapter.for('DeviceCode').syncUpdate(this.getTokenJti(this.dc), {
        scope: 'openid',
        accountId: 'account',
      });
    });

    it('binds the access token to the certificate', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.success', spy);

      await this.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: this.dc,
        })
        .type('form')
        .set('x-ssl-client-cert', crt.replace(/\n/g, ''))
        .expect(200);

      expect(spy).to.have.property('calledOnce', true);
      const { oidc: { entities: { AccessToken } } } = spy.args[0][0];
      expect(AccessToken).to.have.property('x5t#S256', expectedS256);
    });

    it('verifies the request made over MTLS', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);

      await this.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: this.dc,
        })
        .type('form')
        .expect(400)
        .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

      expect(spy).to.have.property('calledOnce', true);
      expect(spy.args[0][0]).to.have.property('error_detail', 'MTLS client certificate missing');
    });
  });

  describe('authorization flow', () => {
    before(function () { return this.login(); });

    beforeEach(async function () {
      const auth = new this.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid',
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
      it('binds the access token to the certificate', async function () {
        const spy = sinon.spy();
        this.provider.once('grant.success', spy);

        await this.agent.post('/token')
          .send({
            client_id: 'client',
            grant_type: 'authorization_code',
            code: this.code,
            redirect_uri: 'https://client.example.com/cb',
          })
          .type('form')
          .set('x-ssl-client-cert', crt.replace(/\n/g, ''))
          .expect(200);

        expect(spy).to.have.property('calledOnce', true);
        const { oidc: { entities: { AccessToken } } } = spy.args[0][0];
        expect(AccessToken).to.have.property('x5t#S256', expectedS256);
      });

      it('verifies the request made over MTLS', async function () {
        const spy = sinon.spy();
        this.provider.once('grant.error', spy);

        await this.agent.post('/token')
          .send({
            client_id: 'client',
            grant_type: 'authorization_code',
            code: this.code,
            redirect_uri: 'https://client.example.com/cb',
          })
          .type('form')
          .expect(400)
          .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

        expect(spy).to.have.property('calledOnce', true);
        expect(spy.args[0][0]).to.have.property('error_detail', 'MTLS client certificate missing');
      });
    });

    describe('refresh_token', () => {
      beforeEach(async function () {
        await this.agent.post('/token')
          .send({
            client_id: 'client',
            grant_type: 'authorization_code',
            code: this.code,
            redirect_uri: 'https://client.example.com/cb',
          })
          .type('form')
          .set('x-ssl-client-cert', crt.replace(/\n/g, ''))
          .expect(({ body }) => {
            this.rt = body.refresh_token;
          });
      });

      it('binds the access token to the certificate', async function () {
        const spy = sinon.spy();
        this.provider.once('grant.success', spy);

        await this.agent.post('/token')
          .send({
            client_id: 'client',
            grant_type: 'refresh_token',
            refresh_token: this.rt,
          })
          .type('form')
          .set('x-ssl-client-cert', crt.replace(/\n/g, ''))
          .expect(200);

        expect(spy).to.have.property('calledOnce', true);
        const { oidc: { entities: { AccessToken } } } = spy.args[0][0];
        expect(AccessToken).to.have.property('x5t#S256', expectedS256);
      });

      it('verifies the request made over MTLS', async function () {
        const spy = sinon.spy();
        this.provider.once('grant.error', spy);

        await this.agent.post('/token')
          .send({
            client_id: 'client',
            grant_type: 'refresh_token',
            refresh_token: this.rt,
          })
          .type('form')
          .expect(400)
          .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

        expect(spy).to.have.property('calledOnce', true);
        expect(spy.args[0][0]).to.have.property('error_detail', 'MTLS client certificate missing');
      });
    });
  });

  describe('client_credentials', () => {
    it('binds the access token to the certificate', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.success', spy);

      await this.agent.post('/token')
        .send({
          grant_type: 'client_credentials',
          client_id: 'client',
        })
        .set('x-ssl-client-cert', crt.replace(/\n/g, ''))
        .type('form')
        .expect(200);

      expect(spy).to.have.property('calledOnce', true);
      const { oidc: { entities: { ClientCredentials } } } = spy.args[0][0];
      expect(ClientCredentials).to.have.property('x5t#S256', expectedS256);
    });

    it('verifies the request was made over MTLS', async function () {
      const spy = sinon.spy();
      this.provider.once('grant.error', spy);

      await this.agent.post('/token')
        .send({
          grant_type: 'client_credentials',
          client_id: 'client',
        })
        .type('form')
        .expect(400)
        .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

      expect(spy).to.have.property('calledOnce', true);
      expect(spy.args[0][0]).to.have.property('error_detail', 'MTLS client certificate missing');
    });
  });
});
