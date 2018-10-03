const { stringify } = require('querystring');
const url = require('url');

const { expect } = require('chai');
const sinon = require('sinon');

const bootstrap = require('../test_helper');

describe('features.resourceIndicators', () => {
  before(bootstrap(__dirname));
  before(function () { return this.login(); });

  afterEach(function () {
    this.provider.removeAllListeners();
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

    it('allows for single resource to be requested', async function () {
      const spy = sinon.spy();
      this.provider.once('token.issued', spy);

      await this.agent.post('/token')
        .send({
          client_id: 'client',
          device_code: this.dc,
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          resource: 'https://client.example.com/api',
        })
        .type('form')
        .expect(200);

      const [token] = spy.firstCall.args;
      expect(token.aud).to.include('https://client.example.com/api');
    });

    it('allows for multiple resources to be requested', async function () {
      const spy = sinon.spy();
      this.provider.once('token.issued', spy);

      await this.agent.post('/token')
        .send(`${stringify({
          client_id: 'client',
          device_code: this.dc,
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        })}&resource=${encodeURIComponent('https://client.example.com/api')}&resource=${encodeURIComponent('https://rs.example.com')}`)
        .type('form')
        .expect(200);

      const [token] = spy.firstCall.args;
      expect(token.aud).to.include('https://client.example.com/api');
      expect(token.aud).to.include('https://rs.example.com');
    });

    it('allows for arbitrary validations to be in place in the audiences helper', async function () {
      await this.agent.post('/token')
        .send({
          client_id: 'client',
          device_code: this.dc,
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          resource: 'http://client.example.com/api',
        })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_resource',
          error_description: 'resources must be https URIs',
        });
    });

    it('ignores the resource parameter on device_authorization_endpoint', async function () {
      const spy = sinon.spy();
      this.provider.once('token.issued', spy);

      await this.agent.post('/device/auth')
        .send({
          client_id: 'client',
          scope: 'openid',
          resource: 'https://client.example.com/api',
        })
        .type('form')
        .expect(200);

      const [token] = spy.firstCall.args;
      expect(token.params).not.to.have.property('resource');
    });
  });

  describe('client_credentials', () => {
    it('allows for single resource to be requested', async function () {
      const spy = sinon.spy();
      this.provider.once('token.issued', spy);

      await this.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'client_credentials',
          resource: 'https://client.example.com/api',
        })
        .type('form')
        .expect(200);

      const [token] = spy.firstCall.args;
      expect(token.aud).to.include('https://client.example.com/api');
    });

    it('allows for multiple resources to be requested', async function () {
      const spy = sinon.spy();
      this.provider.once('token.issued', spy);

      await this.agent.post('/token')
        .send(`${stringify({
          client_id: 'client',
          grant_type: 'client_credentials',
        })}&resource=${encodeURIComponent('https://client.example.com/api')}&resource=${encodeURIComponent('https://rs.example.com')}`)
        .type('form')
        .expect(200);

      const [token] = spy.firstCall.args;
      expect(token.aud).to.include('https://client.example.com/api');
      expect(token.aud).to.include('https://rs.example.com');
    });

    it('allows for arbitrary validations to be in place in the audiences helper', async function () {
      await this.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'client_credentials',
          resource: 'http://client.example.com/api',
        })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_resource',
          error_description: 'resources must be https URIs',
        });
    });
  });

  describe('authorization and token endpoints', () => {
    before(function () { return this.login(); });

    describe('authorization endpoint', () => {
      it('allows for single resource to be requested', async function () {
        const spy = sinon.spy();
        this.provider.once('authorization.success', spy);

        const auth = new this.AuthorizationRequest({
          response_type: 'code token',
          scope: 'openid',
          resource: 'https://client.example.com/api',
        });

        await this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['code', 'state', 'access_token', 'expires_in', 'token_type']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);

        const [{ oidc: { entities: { AccessToken } } }] = spy.firstCall.args;
        expect(AccessToken.aud).to.include('https://client.example.com/api');
      });

      it('allows for multiple resources to be requested', async function () {
        const spy = sinon.spy();
        this.provider.once('authorization.success', spy);

        const auth = new this.AuthorizationRequest({
          response_type: 'code token',
          scope: 'openid',
          resource: ['https://client.example.com/api', 'https://rs.example.com'],
        });

        await this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['code', 'state', 'access_token', 'expires_in', 'token_type']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);

        const [{ oidc: { entities: { AccessToken } } }] = spy.firstCall.args;
        expect(AccessToken.aud).to.include('https://client.example.com/api');
        expect(AccessToken.aud).to.include('https://rs.example.com');
      });

      it('allows for arbitrary validations to be in place in the audiences helper', async function () {
        const spy = sinon.spy();
        this.provider.once('authorization.success', spy);

        const auth = new this.AuthorizationRequest({
          response_type: 'code token',
          scope: 'openid',
          resource: 'http://client.example.com/api',
        });

        await this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_resource'))
          .expect(auth.validateErrorDescription('resources must be https URIs'));
      });
    });

    describe('token endpoint', () => {
      it('allows for single resource to be requested', async function () {
        let spy = sinon.spy();
        this.provider.once('grant.success', spy);

        const auth = new this.AuthorizationRequest({
          response_type: 'code token',
          scope: 'openid',
        });

        let code;
        await this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['code', 'state', 'access_token', 'expires_in', 'token_type']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(({ headers: { location } }) => {
            ({ query: { code } } = url.parse(location, true));
          });

        let AccessToken;
        let refresh_token;
        await this.agent.post('/token')
          .send({
            code,
            client_id: 'client',
            grant_type: 'authorization_code',
            redirect_uri: 'https://client.example.com/cb',
            resource: 'https://client.example.com/api',
          })
          .type('form')
          .expect(200)
          .expect(({ body }) => {
            ({ refresh_token } = body);
          });

        ([{ oidc: { entities: { AccessToken } } }] = spy.firstCall.args);
        expect(AccessToken.aud).to.include('https://client.example.com/api');

        spy = sinon.spy();
        this.provider.once('grant.success', spy);

        await this.agent.post('/token')
          .send({
            refresh_token,
            client_id: 'client',
            grant_type: 'refresh_token',
            resource: 'https://client.example.com/api',
          })
          .type('form')
          .expect(200)
          .expect(({ body }) => {
            ({ refresh_token } = body);
          });

        ([{ oidc: { entities: { AccessToken } } }] = spy.firstCall.args);
        expect(AccessToken.aud).to.include('https://client.example.com/api');
      });

      it('allows for multiple resources to be requested', async function () {
        let spy = sinon.spy();
        this.provider.once('grant.success', spy);

        const auth = new this.AuthorizationRequest({
          response_type: 'code token',
          scope: 'openid',
        });

        let code;
        await this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['code', 'state', 'access_token', 'expires_in', 'token_type']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(({ headers: { location } }) => {
            ({ query: { code } } = url.parse(location, true));
          });

        let AccessToken;
        let refresh_token;
        await this.agent.post('/token')
          .send(`${stringify({
            code,
            client_id: 'client',
            grant_type: 'authorization_code',
            redirect_uri: 'https://client.example.com/cb',
          })}&resource=${encodeURIComponent('https://client.example.com/api')}&resource=${encodeURIComponent('https://rs.example.com')}`)
          .type('form')
          .expect(200)
          .expect(({ body }) => {
            ({ refresh_token } = body);
          });

        ([{ oidc: { entities: { AccessToken } } }] = spy.firstCall.args);
        expect(AccessToken.aud).to.include('https://client.example.com/api');
        expect(AccessToken.aud).to.include('https://rs.example.com');

        spy = sinon.spy();
        this.provider.once('grant.success', spy);

        await this.agent.post('/token')
          .send(`${stringify({
            refresh_token,
            client_id: 'client',
            grant_type: 'refresh_token',
          })}&resource=${encodeURIComponent('https://client.example.com/api')}&resource=${encodeURIComponent('https://rs.example.com')}`)
          .type('form')
          .expect(200)
          .expect(({ body }) => {
            ({ refresh_token } = body);
          });

        ([{ oidc: { entities: { AccessToken } } }] = spy.firstCall.args);
        expect(AccessToken.aud).to.include('https://client.example.com/api');
        expect(AccessToken.aud).to.include('https://rs.example.com');
      });

      it('allows for arbitrary validations to be in place in the audiences helper', async function () {
        const spy = sinon.spy();
        this.provider.once('grant.success', spy);

        const auth = new this.AuthorizationRequest({
          response_type: 'code token',
          scope: 'openid',
        });

        let code;
        await this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['code', 'state', 'access_token', 'expires_in', 'token_type']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(({ headers: { location } }) => {
            ({ query: { code } } = url.parse(location, true));
          });

        await this.agent.post('/token')
          .send({
            code,
            client_id: 'client',
            grant_type: 'authorization_code',
            redirect_uri: 'https://client.example.com/cb',
            resource: 'http://client.example.com/api',
          })
          .type('form')
          .expect(400)
          .expect({
            error: 'invalid_resource',
            error_description: 'resources must be https URIs',
          });
      });
    });
  });

  describe('general resource validations', () => {
    it('validates absolute URIs are provided', async function () {
      await this.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'client_credentials',
          resource: 'client.example.com/api',
        })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_resource',
          error_description: 'resource must be an absolute URI',
        });
    });

    it('validates no query component is present in the resource (1/2)', async function () {
      await this.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'client_credentials',
          resource: 'https://client.example.com/api?',
        })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_resource',
          error_description: 'resource must not contain a query component',
        });
    });

    it('validates no query component is present in the resource (2/2)', async function () {
      await this.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'client_credentials',
          resource: 'https://client.example.com/api?foo=bar',
        })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_resource',
          error_description: 'resource must not contain a query component',
        });
    });

    it('validates no fragment component is present in the resource (1/2)', async function () {
      await this.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'client_credentials',
          resource: 'https://client.example.com/api#',
        })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_resource',
          error_description: 'resource must not contain a fragment component',
        });
    });

    it('validates no fragment component is present in the resource (2/2)', async function () {
      await this.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'client_credentials',
          resource: 'https://client.example.com/api#foo=bar',
        })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_resource',
          error_description: 'resource must not contain a fragment component',
        });
    });
  });
});
