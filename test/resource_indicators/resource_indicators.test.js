const { stringify } = require('querystring');
const url = require('url');

const { expect } = require('chai');
const sinon = require('sinon');

const bootstrap = require('../test_helper');

const { formats: { AccessToken: FORMAT } } = global.TEST_CONFIGURATION_DEFAULTS;
const allowMultiple = ['opaque', 'jwt'].includes(FORMAT);

describe('features.resourceIndicators', () => {
  before(bootstrap(__dirname));
  before(function () { return this.login(); });

  afterEach(function () {
    this.provider.removeAllListeners();
  });

  describe('urn:ietf:params:oauth:grant-type:device_code', () => {
    describe('requested with device authorization request', () => {
      it('allows for single resource to be requested (1/2)', async function () {
        let deviceCode;
        await this.agent.post('/device/auth')
          .send({
            client_id: 'client',
            scope: 'openid',
            resource: 'https://client.example.com/api',
          })
          .type('form')
          .expect(200)
          .expect(({ body: { device_code: dc } }) => {
            deviceCode = dc;
          });
        const adapter = this.TestAdapter.for('DeviceCode');
        const jti = this.getTokenJti(deviceCode);

        expect(
          adapter.syncFind(jti),
        ).to.have.nested.property('params.resource', 'https://client.example.com/api');

        adapter.syncUpdate(jti, {
          scope: 'openid',
          accountId: 'account',
          resource: 'https://client.example.com/api',
        });

        const spy = sinon.spy();
        this.provider.once('access_token.saved', spy);

        await this.agent.post('/token')
          .send({
            client_id: 'client',
            device_code: deviceCode,
            grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          })
          .type('form')
          .expect(200);

        const [token] = spy.firstCall.args;
        expect(token.aud).to.include('https://client.example.com/api');
      });

      it('allows for single resource to be requested (2/2)', async function () {
        let deviceCode;
        await this.agent.post('/device/auth')
          .send({
            client_id: 'client',
            scope: 'openid',
            resource: 'urn:foo:bar',
          })
          .type('form')
          .expect(200)
          .expect(({ body: { device_code: dc } }) => {
            deviceCode = dc;
          });
        const adapter = this.TestAdapter.for('DeviceCode');
        const jti = this.getTokenJti(deviceCode);

        expect(
          adapter.syncFind(jti),
        ).to.have.nested.property('params.resource', 'urn:foo:bar');

        adapter.syncUpdate(jti, {
          scope: 'openid',
          accountId: 'account',
          resource: 'urn:foo:bar',
        });

        const spy = sinon.spy();
        this.provider.once('access_token.saved', spy);

        await this.agent.post('/token')
          .send({
            client_id: 'client',
            device_code: deviceCode,
            grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          })
          .type('form')
          .expect(200);

        const [token] = spy.firstCall.args;
        expect(token.aud).to.include('urn:foo:bar');
      });

      if (allowMultiple) {
        it('allows for multiple resources to be requested', async function () {
          let deviceCode;
          await this.agent.post('/device/auth')
            .send(`${stringify({
              client_id: 'client',
              scope: 'openid',
            })}&resource=${encodeURIComponent('https://client.example.com/api')}&resource=${encodeURIComponent('https://rs.example.com')}`)
            .type('form')
            .expect(200)
            .expect(({ body: { device_code: dc } }) => {
              deviceCode = dc;
            });

          const adapter = this.TestAdapter.for('DeviceCode');
          const jti = this.getTokenJti(deviceCode);

          expect(
            adapter.syncFind(jti),
          ).to.have.deep.nested.property('params.resource', ['https://client.example.com/api', 'https://rs.example.com']);

          adapter.syncUpdate(jti, {
            scope: 'openid',
            accountId: 'account',
            resource: ['https://client.example.com/api', 'https://rs.example.com'],
          });

          const spy = sinon.spy();
          this.provider.once('access_token.saved', spy);

          await this.agent.post('/token')
            .send({
              client_id: 'client',
              device_code: deviceCode,
              grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
            })
            .type('form')
            .expect(200);

          const [token] = spy.firstCall.args;
          expect(token.aud).to.include('https://client.example.com/api');
          expect(token.aud).to.include('https://rs.example.com');
        });
      } else if (typeof FORMAT !== 'function') {
        it('does not allow multiple resources to be added to an issued access token', async function () {
          let deviceCode;
          await this.agent.post('/device/auth')
            .send(`${stringify({
              client_id: 'client',
              scope: 'openid',
            })}&resource=${encodeURIComponent('https://client.example.com/api')}&resource=${encodeURIComponent('https://rs.example.com')}`)
            .type('form')
            .expect(200)
            .expect(({ body: { device_code: dc } }) => {
              deviceCode = dc;
            });

          const adapter = this.TestAdapter.for('DeviceCode');
          const jti = this.getTokenJti(deviceCode);

          expect(
            adapter.syncFind(jti),
          ).to.have.deep.nested.property('params.resource', ['https://client.example.com/api', 'https://rs.example.com']);

          adapter.syncUpdate(jti, {
            scope: 'openid',
            accountId: 'account',
            resource: ['https://client.example.com/api', 'https://rs.example.com'],
          });

          const spy = sinon.spy();
          this.provider.on('server_error', spy);

          await this.agent.post('/token')
            .send({
              client_id: 'client',
              device_code: deviceCode,
              grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
            })
            .type('form')
            .expect(500)
            .expect((response) => {
              expect(response.body).to.have.property('error', 'server_error');
              expect(response.body).to.have.property('error_description', 'oops! something went wrong');
            });

          expect(spy).to.have.property('calledOnce', true);
          const error = spy.firstCall.args[1];
          expect(error).to.be.an.instanceof(Error);
          expect(error).to.have.property('message', 'only a single audience ("aud") value is permitted for this token type');
        });
      }

      it('runs the allowedPolicy helper to determine whether a resource can be used', function () {
        return this.agent.post('/device/auth')
          .send({
            client_id: 'client',
            scope: 'openid',
            resource: 'urn:example:bad',
          })
          .type('form')
          .expect(400)
          .expect({ error: 'invalid_target', error_description: 'requested resource or resources are not permitted' });
      });

      it('allows for arbitrary validations to be in place in the audiences helper', async function () {
        let deviceCode;
        await this.agent.post('/device/auth')
          .send({
            client_id: 'client',
            scope: 'openid',
            resource: 'http://client.example.com/api',
          })
          .type('form')
          .expect(200)
          .expect(({ body: { device_code: dc } }) => {
            deviceCode = dc;
          });
        const adapter = this.TestAdapter.for('DeviceCode');
        const jti = this.getTokenJti(deviceCode);

        expect(
          adapter.syncFind(jti),
        ).to.have.nested.property('params.resource', 'http://client.example.com/api');

        adapter.syncUpdate(jti, {
          scope: 'openid',
          accountId: 'account',
          resource: 'http://client.example.com/api',
        });

        await this.agent.post('/token')
          .send({
            client_id: 'client',
            device_code: deviceCode,
            grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          })
          .type('form')
          .expect(400)
          .expect({
            error: 'invalid_target',
            error_description: 'resources must be https URIs or URNs',
          });
      });
    });

    describe('requested at the token endpoint', () => {
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

      it('allows for single resource to be requested (1/2)', async function () {
        const spy = sinon.spy();
        this.provider.once('access_token.saved', spy);

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

      it('allows for single resource to be requested (2/2)', async function () {
        const spy = sinon.spy();
        this.provider.once('access_token.saved', spy);

        await this.agent.post('/token')
          .send({
            client_id: 'client',
            device_code: this.dc,
            grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
            resource: 'urn:foo:bar',
          })
          .type('form')
          .expect(200);

        const [token] = spy.firstCall.args;
        expect(token.aud).to.include('urn:foo:bar');
      });

      if (allowMultiple) {
        it('allows for multiple resources to be requested', async function () {
          const spy = sinon.spy();
          this.provider.once('access_token.saved', spy);

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
      } else if (typeof FORMAT !== 'function') {
        it('does not allow multiple resources to be added to an issued access token', async function () {
          const spy = sinon.spy();
          this.provider.once('server_error', spy);

          await this.agent.post('/token')
            .send(`${stringify({
              client_id: 'client',
              device_code: this.dc,
              grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
            })}&resource=${encodeURIComponent('https://client.example.com/api')}&resource=${encodeURIComponent('https://rs.example.com')}`)
            .type('form')
            .expect(500)
            .expect((response) => {
              expect(response.body).to.have.property('error', 'server_error');
              expect(response.body).to.have.property('error_description', 'oops! something went wrong');
            });

          expect(spy).to.have.property('calledOnce', true);
          const error = spy.firstCall.args[1];
          expect(error).to.be.an.instanceof(Error);
          expect(error).to.have.property('message', 'only a single audience ("aud") value is permitted for this token type');
        });
      }

      it('runs the allowedPolicy helper to determine whether a resource can be used', function () {
        return this.agent.post('/token')
          .send({
            client_id: 'client',
            device_code: this.dc,
            grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
            resource: 'urn:example:bad',
          })
          .type('form')
          .expect(400)
          .expect({
            error: 'invalid_target',
            error_description: 'requested resource or resources are not permitted',
          });
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
            error: 'invalid_target',
            error_description: 'resources must be https URIs or URNs',
          });
      });
    });
  });

  describe('client_credentials', () => {
    it('allows for single resource to be requested (1/2)', async function () {
      const spy = sinon.spy();
      this.provider.once('client_credentials.saved', spy);

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

    it('allows for single resource to be requested (2/2)', async function () {
      const spy = sinon.spy();
      this.provider.once('client_credentials.saved', spy);

      await this.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'client_credentials',
          resource: 'urn:foo:bar',
        })
        .type('form')
        .expect(200);

      const [token] = spy.firstCall.args;
      expect(token.aud).to.include('urn:foo:bar');
    });

    if (allowMultiple) {
      it('allows for multiple resources to be requested', async function () {
        const spy = sinon.spy();
        this.provider.once('client_credentials.saved', spy);

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
    } else if (typeof FORMAT !== 'function') {
      it('does not allow multiple resources to be added to an issued access token', async function () {
        const spy = sinon.spy();
        this.provider.on('server_error', spy);

        await this.agent.post('/token')
          .send(`${stringify({
            client_id: 'client',
            grant_type: 'client_credentials',
          })}&resource=${encodeURIComponent('https://client.example.com/api')}&resource=${encodeURIComponent('https://rs.example.com')}`)
          .type('form')
          .expect(500)
          .expect((response) => {
            expect(response.body).to.have.property('error', 'server_error');
            expect(response.body).to.have.property('error_description', 'oops! something went wrong');
          });

        expect(spy).to.have.property('calledOnce', true);
        const error = spy.firstCall.args[1];
        expect(error).to.be.an.instanceof(Error);
        expect(error).to.have.property('message', 'only a single audience ("aud") value is permitted for this token type');
      });
    }

    it('runs the allowedPolicy helper to determine whether a resource can be used', function () {
      return this.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'client_credentials',
          resource: 'urn:example:bad',
        })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_target',
          error_description: 'requested resource or resources are not permitted',
        });
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
          error: 'invalid_target',
          error_description: 'resources must be https URIs or URNs',
        });
    });
  });

  describe('authorization and token endpoints', () => {
    before(function () { return this.login(); });

    describe('authorization endpoint', () => {
      it('allows for single resource to be requested (1/2)', async function () {
        const spy = sinon.spy();
        this.provider.once('authorization.success', spy);

        const auth = new this.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          resource: 'https://client.example.com/api',
        });

        await this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token', 'state', 'access_token', 'expires_in', 'token_type', 'scope']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);

        const [{ oidc: { entities: { AccessToken } } }] = spy.firstCall.args;
        expect(AccessToken.aud).to.include('https://client.example.com/api');
      });

      it('allows for single resource to be requested (2/2)', async function () {
        const spy = sinon.spy();
        this.provider.once('authorization.success', spy);

        const auth = new this.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          resource: 'urn:foo:bar',
        });

        await this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token', 'state', 'access_token', 'expires_in', 'token_type', 'scope']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);

        const [{ oidc: { entities: { AccessToken } } }] = spy.firstCall.args;
        expect(AccessToken.aud).to.include('urn:foo:bar');
      });

      if (allowMultiple) {
        it('allows for multiple resources to be requested', async function () {
          const spy = sinon.spy();
          this.provider.once('authorization.success', spy);

          const auth = new this.AuthorizationRequest({
            response_type: 'id_token token',
            scope: 'openid',
            resource: ['https://client.example.com/api', 'https://rs.example.com'],
          });

          await this.wrap({ route: '/auth', verb: 'get', auth })
            .expect(302)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['id_token', 'state', 'access_token', 'expires_in', 'token_type', 'scope']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation);

          const [{ oidc: { entities: { AccessToken } } }] = spy.firstCall.args;
          expect(AccessToken.aud).to.include('https://client.example.com/api');
          expect(AccessToken.aud).to.include('https://rs.example.com');
        });
      } else if (typeof FORMAT !== 'function') {
        it('does not allow multiple resources to be added to an issued access token', async function () {
          const spy = sinon.spy();
          this.provider.once('server_error', spy);

          const auth = new this.AuthorizationRequest({
            response_type: 'id_token token',
            scope: 'openid',
            resource: ['https://client.example.com/api', 'https://rs.example.com'],
          });

          await this.wrap({ route: '/auth', verb: 'get', auth })
            .expect(302)
            .expect(auth.validateFragment)
            .expect(auth.validatePresence(['state', 'error', 'error_description']))
            .expect(auth.validateState)
            .expect(auth.validateClientLocation)
            .expect(auth.validateError('server_error'))
            .expect(auth.validateErrorDescription('oops! something went wrong'));

          expect(spy).to.have.property('calledOnce', true);
          const error = spy.firstCall.args[1];
          expect(error).to.be.an.instanceof(Error);
          expect(error).to.have.property('message', 'only a single audience ("aud") value is permitted for this token type');
        });
      }

      it('runs the allowedPolicy helper to determine whether a resource can be used', async function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          resource: 'urn:example:bad',
        });

        await this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_target'))
          .expect(auth.validateErrorDescription('requested resource or resources are not permitted'));
      });

      it('allows for arbitrary validations to be in place in the audiences helper', async function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'id_token token',
          scope: 'openid',
          resource: 'http://client.example.com/api',
        });

        await this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(302)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_target'))
          .expect(auth.validateErrorDescription('resources must be https URIs or URNs'));
      });
    });

    describe('token endpoint', () => {
      bootstrap.skipConsent();

      it('allows for single resource to be requested (1/2)', async function () {
        let spy = sinon.spy();
        this.provider.once('grant.success', spy);

        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid offline_access',
          prompt: 'consent',
          resource: 'https://client.example.com/api',
        });

        let code;
        await this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(302)
          .expect(auth.validatePresence(['code', 'state']))
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
          })
          .type('form')
          .expect(200)
          .expect(({ body }) => {
            ({ refresh_token } = body);
          });

        ([{ oidc: { entities: { AccessToken } } }] = spy.firstCall.args);
        expect(AccessToken.aud).to.include('https://client.example.com/api');
      });

      it('allows for single resource to be requested (2/2)', async function () {
        let spy = sinon.spy();
        this.provider.once('grant.success', spy);

        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid offline_access',
          prompt: 'consent',
          resource: 'urn:foo:bar',
        });

        let code;
        await this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(302)
          .expect(auth.validatePresence(['code', 'state']))
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
          })
          .type('form')
          .expect(200)
          .expect(({ body }) => {
            ({ refresh_token } = body);
          });

        ([{ oidc: { entities: { AccessToken } } }] = spy.firstCall.args);
        expect(AccessToken.aud).to.include('urn:foo:bar');

        spy = sinon.spy();
        this.provider.once('grant.success', spy);

        await this.agent.post('/token')
          .send({
            refresh_token,
            client_id: 'client',
            grant_type: 'refresh_token',
          })
          .type('form')
          .expect(200)
          .expect(({ body }) => {
            ({ refresh_token } = body);
          });

        ([{ oidc: { entities: { AccessToken } } }] = spy.firstCall.args);
        expect(AccessToken.aud).to.include('urn:foo:bar');
      });

      if (allowMultiple) {
        it('allows for multiple resources to be requested', async function () {
          let spy = sinon.spy();
          this.provider.once('grant.success', spy);

          const auth = new this.AuthorizationRequest({
            response_type: 'code',
            scope: 'openid offline_access',
            prompt: 'consent',
            resource: ['https://client.example.com/api', 'https://rs.example.com'],
          });

          let code;
          await this.wrap({ route: '/auth', verb: 'get', auth })
            .expect(302)
            .expect(auth.validatePresence(['code', 'state']))
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
            })
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
            .send({
              refresh_token,
              client_id: 'client',
              grant_type: 'refresh_token',
            })
            .type('form')
            .expect(200)
            .expect(({ body }) => {
              ({ refresh_token } = body);
            });

          ([{ oidc: { entities: { AccessToken } } }] = spy.firstCall.args);
          expect(AccessToken.aud).to.include('https://client.example.com/api');
          expect(AccessToken.aud).to.include('https://rs.example.com');
        });
      } else if (typeof FORMAT !== 'function') {
        it('does not allow multiple resources to be added to an issued access token', async function () {
          const spy = sinon.spy();
          this.provider.once('server_error', spy);

          const auth = new this.AuthorizationRequest({
            response_type: 'code',
            scope: 'openid offline_access',
            prompt: 'consent',
            resource: ['https://client.example.com/api', 'https://rs.example.com'],
          });

          let code;
          await this.wrap({ route: '/auth', verb: 'get', auth })
            .expect(302)
            .expect(auth.validatePresence(['code', 'state']))
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
            })
            .type('form')
            .expect(500)
            .expect((response) => {
              expect(response.body).to.have.property('error', 'server_error');
              expect(response.body).to.have.property('error_description', 'oops! something went wrong');
            });

          expect(spy).to.have.property('calledOnce', true);
          const error = spy.firstCall.args[1];
          expect(error).to.be.an.instanceof(Error);
          expect(error).to.have.property('message', 'only a single audience ("aud") value is permitted for this token type');
        });
      }

      it('runs the allowedPolicy helper to determine whether a resource can be used', async function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
        });

        let code;
        await this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(302)
          .expect(auth.validatePresence(['code', 'state']))
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
            resource: 'urn:example:bad',
          })
          .type('form')
          .expect(400)
          .expect({
            error: 'invalid_target',
            error_description: 'requested resource or resources are not permitted',
          });
      });

      it('allows for arbitrary validations to be in place in the audiences helper (1/2)', async function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
          resource: 'http://client.example.com/api',
        });

        let code;
        await this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(302)
          .expect(auth.validatePresence(['code', 'state']))
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
          })
          .type('form')
          .expect(400)
          .expect({
            error: 'invalid_target',
            error_description: 'resources must be https URIs or URNs',
          });
      });

      it('allows for arbitrary validations to be in place in the audiences helper (2/2)', async function () {
        const auth = new this.AuthorizationRequest({
          response_type: 'code',
          scope: 'openid',
        });

        let code;
        await this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(302)
          .expect(auth.validatePresence(['code', 'state']))
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
            error: 'invalid_target',
            error_description: 'resources must be https URIs or URNs',
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
          error: 'invalid_target',
          error_description: 'resource must be an absolute URI',
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
          error: 'invalid_target',
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
          error: 'invalid_target',
          error_description: 'resource must not contain a fragment component',
        });
    });
  });
});
