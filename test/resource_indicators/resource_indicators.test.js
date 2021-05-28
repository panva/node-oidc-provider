/* eslint-disable prefer-destructuring */

const { strict: assert } = require('assert');

const sinon = require('sinon');
const { expect } = require('chai');

const bootstrap = require('../test_helper');
const { features: { resourceIndicators: defaults } } = require('../../lib/helpers/defaults')();

describe('features.resourceIndicators defaults', () => {
  it('defaultResource', async () => {
    expect(await defaults.defaultResource()).to.be.undefined;
    expect(await defaults.defaultResource(undefined, undefined, ['urn:example:rs'])).to.deep.equal(['urn:example:rs']);
  });

  it('getResourceServerInfo', () => assert.rejects(defaults.getResourceServerInfo(), (err) => {
    expect(err.message).to.equal('invalid_target');
    expect(err.error_description).to.equal('resource indicator is missing, or unknown');
    return true;
  }));
});

describe('features.resourceIndicators', () => {
  before(bootstrap(__dirname));
  before(function () {
    return this.login({
      resources: {
        'urn:wl:default': 'api:read api:write',
        'urn:wl:explicit': 'api:read api:write',
      },
    });
  });

  describe('resource validations', () => {
    it('must be a URI', function () {
      return this.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'client_credentials',
          scope: 'api:read',
          resource: 'wl-not-a-uri',
        })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_target',
          error_description: 'resource indicator must be an absolute URI',
        });
    });

    it('must not contain a fragment', function () {
      return this.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'client_credentials',
          scope: 'api:read',
          resource: 'urn:wl:foo/bar#',
        })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_target',
          error_description: 'resource indicator must not contain a fragment component',
        });
    });
  });

  ['get', 'post'].forEach((verb) => {
    describe(`${verb} response_type includes token`, () => {
      const response_type = 'id_token token';

      it('checks the policy and adds the resource', async function () {
        const spy = sinon.spy();
        this.provider.once('access_token.saved', spy);
        this.provider.once('access_token.issued', spy);

        const auth = new this.AuthorizationRequest({
          response_type,
          resource: 'urn:not:allowed',
          scope: 'openid api:read',
        });

        await this.wrap({ route: '/auth', verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_target'))
          .expect(auth.validateErrorDescription('resource indicator is missing, or unknown'));

        auth.resource = 'urn:wl:explicit';
        await this.wrap({ route: '/auth', verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token', 'state', 'access_token', 'expires_in', 'token_type', 'scope']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);

        expect(spy.calledOnce).to.be.true;
        const token = spy.args[0][0];
        expect(token.aud).to.equal('urn:wl:explicit');
      });

      it('applies the default resource', async function () {
        const spy = sinon.spy();
        this.provider.once('access_token.saved', spy);
        this.provider.once('access_token.issued', spy);

        const auth = new this.AuthorizationRequest({
          response_type,
          scope: 'openid api:read',
        });

        await this.wrap({ route: '/auth', verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token', 'state', 'access_token', 'expires_in', 'token_type', 'scope']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);

        expect(spy.calledOnce).to.be.true;
        const token = spy.args[0][0];
        expect(token.aud).to.equal('urn:wl:default');
      });
    });

    describe(`${verb} response_type includes code`, () => {
      const response_type = 'code';

      it('checks the policy and adds the resource', async function () {
        const spy = sinon.spy();
        this.provider.once('authorization_code.saved', spy);

        const auth = new this.AuthorizationRequest({
          response_type,
          resource: 'urn:not:allowed',
          scope: 'api:read',
        });

        await this.wrap({ route: '/auth', verb, auth })
          .expect(303)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_target'))
          .expect(auth.validateErrorDescription('resource indicator is missing, or unknown'));

        auth.resource = 'urn:wl:explicit';
        await this.wrap({ route: '/auth', verb, auth })
          .expect(303)
          .expect(auth.validatePresence(['code', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);

        expect(spy.calledOnce).to.be.true;
        const code = spy.args[0][0];
        expect(code.resource).to.equal('urn:wl:explicit');

        const spy2 = sinon.spy();
        this.provider.once('access_token.saved', spy2);
        this.provider.once('access_token.issued', spy2);
        const spy3 = sinon.spy();
        this.provider.once('refresh_token.saved', spy3);

        await this.agent.post('/token')
          .send({
            client_id: 'client',
            grant_type: 'authorization_code',
            code: code.jti,
          })
          .type('form')
          .expect(200);

        expect(spy2.calledOnce).to.be.true;
        let at = spy2.args[0][0];
        expect(at.aud).to.equal('urn:wl:explicit');

        expect(spy3.calledOnce).to.be.true;
        let rt = spy3.args[0][0];
        expect(rt.resource).to.equal('urn:wl:explicit');

        const spy4 = sinon.spy();
        this.provider.once('access_token.saved', spy4);
        this.provider.once('access_token.issued', spy4);
        const spy5 = sinon.spy();
        this.provider.once('refresh_token.saved', spy5);

        await this.agent.post('/token')
          .send({
            client_id: 'client',
            grant_type: 'refresh_token',
            refresh_token: rt.jti,
          })
          .type('form')
          .expect(200);

        expect(spy4.calledOnce).to.be.true;
        at = spy4.args[0][0];
        expect(at.aud).to.equal('urn:wl:explicit');

        expect(spy5.calledOnce).to.be.true;
        rt = spy5.args[0][0];
        expect(rt.resource).to.equal('urn:wl:explicit');
      });

      it('applies the default resource', async function () {
        const spy = sinon.spy();
        this.provider.once('authorization_code.saved', spy);

        const auth = new this.AuthorizationRequest({
          response_type,
          scope: 'api:read',
        });

        await this.wrap({ route: '/auth', verb, auth })
          .expect(303)
          .expect(auth.validatePresence(['code', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);

        expect(spy.calledOnce).to.be.true;
        const code = spy.args[0][0];
        expect(code.resource).to.equal('urn:wl:default');

        const spy2 = sinon.spy();
        this.provider.once('access_token.saved', spy2);
        this.provider.once('access_token.issued', spy2);
        const spy3 = sinon.spy();
        this.provider.once('refresh_token.saved', spy3);

        await this.agent.post('/token')
          .send({
            client_id: 'client',
            grant_type: 'authorization_code',
            code: code.jti,
          })
          .type('form')
          .expect(200);

        expect(spy2.calledOnce).to.be.true;
        let at = spy2.args[0][0];
        expect(at.aud).to.equal('urn:wl:default');

        expect(spy3.calledOnce).to.be.true;
        let rt = spy3.args[0][0];
        expect(rt.resource).to.equal('urn:wl:default');

        const spy4 = sinon.spy();
        this.provider.once('access_token.saved', spy4);
        this.provider.once('access_token.issued', spy4);
        const spy5 = sinon.spy();
        this.provider.once('refresh_token.saved', spy5);

        await this.agent.post('/token')
          .send({
            client_id: 'client',
            grant_type: 'refresh_token',
            refresh_token: rt.jti,
          })
          .type('form')
          .expect(200);

        expect(spy4.calledOnce).to.be.true;
        at = spy4.args[0][0];
        expect(at.aud).to.equal('urn:wl:default');

        expect(spy5.calledOnce).to.be.true;
        rt = spy5.args[0][0];
        expect(rt.resource).to.equal('urn:wl:default');
      });

      it('applies the default resource (when useGrantedResource returns true)', async function () {
        const spy = sinon.spy();
        this.provider.once('authorization_code.saved', spy);

        const auth = new this.AuthorizationRequest({
          response_type,
          scope: 'openid api:read',
        });

        await this.wrap({ route: '/auth', verb, auth })
          .expect(303)
          .expect(auth.validatePresence(['code', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);

        expect(spy.calledOnce).to.be.true;
        const code = spy.args[0][0];
        expect(code.resource).to.equal('urn:wl:default');

        const spy2 = sinon.spy();
        this.provider.once('access_token.saved', spy2);
        this.provider.once('access_token.issued', spy2);
        const spy3 = sinon.spy();
        this.provider.once('refresh_token.saved', spy3);

        await this.agent.post('/token')
          .send({
            client_id: 'client',
            grant_type: 'authorization_code',
            code: code.jti,
            usegranted: true,
          })
          .type('form')
          .expect(200);

        expect(spy2.calledOnce).to.be.true;
        let at = spy2.args[0][0];
        expect(at.aud).to.equal('urn:wl:default');

        expect(spy3.calledOnce).to.be.true;
        let rt = spy3.args[0][0];
        expect(rt.resource).to.equal('urn:wl:default');

        const spy4 = sinon.spy();
        this.provider.once('access_token.saved', spy4);
        this.provider.once('access_token.issued', spy4);
        const spy5 = sinon.spy();
        this.provider.once('refresh_token.saved', spy5);

        await this.agent.post('/token')
          .send({
            client_id: 'client',
            grant_type: 'refresh_token',
            refresh_token: rt.jti,
            usegranted: true,
          })
          .type('form')
          .expect(200);

        expect(spy4.calledOnce).to.be.true;
        at = spy4.args[0][0];
        expect(at.aud).to.equal('urn:wl:default');

        expect(spy5.calledOnce).to.be.true;
        rt = spy5.args[0][0];
        expect(rt.resource).to.equal('urn:wl:default');
      });

      it('applies the explicit resource', async function () {
        const spy = sinon.spy();
        this.provider.once('authorization_code.saved', spy);

        const auth = new this.AuthorizationRequest({
          response_type,
          scope: 'openid api:read',
        });

        await this.wrap({ route: '/auth', verb, auth })
          .expect(303)
          .expect(auth.validatePresence(['code', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);

        expect(spy.calledOnce).to.be.true;
        const code = spy.args[0][0];
        expect(code.resource).to.equal('urn:wl:default');

        const spy2 = sinon.spy();
        this.provider.once('access_token.saved', spy2);
        this.provider.once('access_token.issued', spy2);
        const spy3 = sinon.spy();
        this.provider.once('refresh_token.saved', spy3);

        await this.agent.post('/token')
          .send({
            client_id: 'client',
            grant_type: 'authorization_code',
            code: code.jti,
            resource: 'urn:wl:default',
          })
          .type('form')
          .expect(200);

        expect(spy2.calledOnce).to.be.true;
        let at = spy2.args[0][0];
        expect(at.aud).to.equal('urn:wl:default');

        expect(spy3.calledOnce).to.be.true;
        let rt = spy3.args[0][0];
        expect(rt.resource).to.equal('urn:wl:default');

        const spy4 = sinon.spy();
        this.provider.once('access_token.saved', spy4);
        this.provider.once('access_token.issued', spy4);
        const spy5 = sinon.spy();
        this.provider.once('refresh_token.saved', spy5);

        await this.agent.post('/token')
          .send({
            client_id: 'client',
            grant_type: 'refresh_token',
            refresh_token: rt.jti,
            resource: 'urn:wl:default',
          })
          .type('form')
          .expect(200);

        expect(spy4.calledOnce).to.be.true;
        at = spy4.args[0][0];
        expect(at.aud).to.equal('urn:wl:default');

        expect(spy5.calledOnce).to.be.true;
        rt = spy5.args[0][0];
        expect(rt.resource).to.equal('urn:wl:default');
      });
    });
  });

  describe('urn:ietf:params:oauth:grant-type:device_code', () => {
    it('checks the policy and adds the resource', async function () {
      await this.agent.post('/device/auth')
        .send({
          client_id: 'client',
          resource: 'urn:not:allowed',
          scope: 'api:read',
        })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_target',
          error_description: 'resource indicator is missing, or unknown',
        });

      let user_code;
      let device_code;
      await this.agent.post('/device/auth')
        .send({
          client_id: 'client',
          resource: 'urn:wl:explicit',
          scope: 'api:read',
        })
        .type('form')
        .expect(200)
        .expect(({ body }) => {
          ({ user_code, device_code } = body);
        });

      this.getSession().state = { secret: 'foo' };

      await this.agent.post('/device')
        .send({
          user_code,
          xsrf: 'foo',
          confirm: true,
        })
        .type('form')
        .expect(200);

      const spy = sinon.spy();
      this.provider.once('access_token.saved', spy);
      this.provider.once('access_token.issued', spy);
      const spy2 = sinon.spy();
      this.provider.once('refresh_token.saved', spy2);

      await this.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code,
        })
        .type('form')
        .expect(200);

      expect(spy.calledOnce).to.be.true;
      let at = spy.args[0][0];
      expect(at.aud).to.equal('urn:wl:explicit');

      expect(spy2.calledOnce).to.be.true;
      let rt = spy2.args[0][0];
      expect(rt.resource).to.equal('urn:wl:explicit');

      const spy3 = sinon.spy();
      this.provider.once('access_token.saved', spy3);
      this.provider.once('access_token.issued', spy3);
      const spy4 = sinon.spy();
      this.provider.once('refresh_token.saved', spy4);

      await this.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'refresh_token',
          refresh_token: rt.jti,
        })
        .type('form')
        .expect(200);

      expect(spy3.calledOnce).to.be.true;
      at = spy3.args[0][0];
      expect(at.aud).to.equal('urn:wl:explicit');

      expect(spy4.calledOnce).to.be.true;
      rt = spy4.args[0][0];
      expect(rt.resource).to.equal('urn:wl:explicit');
    });

    it('applies the default resource', async function () {
      let user_code;
      let device_code;
      await this.agent.post('/device/auth')
        .send({
          client_id: 'client',
          scope: 'api:read',
        })
        .type('form')
        .expect(200)
        .expect(({ body }) => {
          ({ user_code, device_code } = body);
        });

      this.getSession().state = { secret: 'foo' };

      await this.agent.post('/device')
        .send({
          user_code,
          xsrf: 'foo',
          confirm: true,
        })
        .type('form')
        .expect(200);

      const spy = sinon.spy();
      this.provider.once('access_token.saved', spy);
      this.provider.once('access_token.issued', spy);
      const spy2 = sinon.spy();
      this.provider.once('refresh_token.saved', spy2);

      await this.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code,
        })
        .type('form')
        .expect(200);

      expect(spy.calledOnce).to.be.true;
      let at = spy.args[0][0];
      expect(at.aud).to.equal('urn:wl:default');

      expect(spy2.calledOnce).to.be.true;
      let rt = spy2.args[0][0];
      expect(rt.resource).to.equal('urn:wl:default');

      const spy3 = sinon.spy();
      this.provider.once('access_token.saved', spy3);
      this.provider.once('access_token.issued', spy3);
      const spy4 = sinon.spy();
      this.provider.once('refresh_token.saved', spy4);

      await this.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'refresh_token',
          refresh_token: rt.jti,
        })
        .type('form')
        .expect(200);

      expect(spy3.calledOnce).to.be.true;
      at = spy3.args[0][0];
      expect(at.aud).to.equal('urn:wl:default');

      expect(spy4.calledOnce).to.be.true;
      rt = spy4.args[0][0];
      expect(rt.resource).to.equal('urn:wl:default');
    });

    it('applies the default resource (when useGrantedResource returns true)', async function () {
      let user_code;
      let device_code;
      await this.agent.post('/device/auth')
        .send({
          client_id: 'client',
          scope: 'openid api:read',
        })
        .type('form')
        .expect(200)
        .expect(({ body }) => {
          ({ user_code, device_code } = body);
        });

      this.getSession().state = { secret: 'foo' };

      await this.agent.post('/device')
        .send({
          user_code,
          xsrf: 'foo',
          confirm: true,
        })
        .type('form')
        .expect(200);

      const spy = sinon.spy();
      this.provider.once('access_token.saved', spy);
      this.provider.once('access_token.issued', spy);
      const spy2 = sinon.spy();
      this.provider.once('refresh_token.saved', spy2);

      await this.agent.post('/token')
        .send({
          client_id: 'client',
          usegranted: true,
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code,
        })
        .type('form')
        .expect(200);

      expect(spy.calledOnce).to.be.true;
      let at = spy.args[0][0];
      expect(at.aud).to.equal('urn:wl:default');

      expect(spy2.calledOnce).to.be.true;
      let rt = spy2.args[0][0];
      expect(rt.resource).to.equal('urn:wl:default');

      const spy3 = sinon.spy();
      this.provider.once('access_token.saved', spy3);
      this.provider.once('access_token.issued', spy3);
      const spy4 = sinon.spy();
      this.provider.once('refresh_token.saved', spy4);

      await this.agent.post('/token')
        .send({
          client_id: 'client',
          usegranted: true,
          grant_type: 'refresh_token',
          refresh_token: rt.jti,
        })
        .type('form')
        .expect(200);

      expect(spy3.calledOnce).to.be.true;
      at = spy3.args[0][0];
      expect(at.aud).to.equal('urn:wl:default');

      expect(spy4.calledOnce).to.be.true;
      rt = spy4.args[0][0];
      expect(rt.resource).to.equal('urn:wl:default');
    });

    it('applies the explicit resource', async function () {
      let user_code;
      let device_code;
      await this.agent.post('/device/auth')
        .send({
          client_id: 'client',
          scope: 'openid api:read',
        })
        .type('form')
        .expect(200)
        .expect(({ body }) => {
          ({ user_code, device_code } = body);
        });

      this.getSession().state = { secret: 'foo' };

      await this.agent.post('/device')
        .send({
          user_code,
          xsrf: 'foo',
          confirm: true,
        })
        .type('form')
        .expect(200);

      const spy = sinon.spy();
      this.provider.once('access_token.saved', spy);
      this.provider.once('access_token.issued', spy);
      const spy2 = sinon.spy();
      this.provider.once('refresh_token.saved', spy2);

      await this.agent.post('/token')
        .send({
          client_id: 'client',
          resource: 'urn:wl:default',
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code,
        })
        .type('form')
        .expect(200);

      expect(spy.calledOnce).to.be.true;
      let at = spy.args[0][0];
      expect(at.aud).to.equal('urn:wl:default');

      expect(spy2.calledOnce).to.be.true;
      let rt = spy2.args[0][0];
      expect(rt.resource).to.equal('urn:wl:default');

      const spy3 = sinon.spy();
      this.provider.once('access_token.saved', spy3);
      this.provider.once('access_token.issued', spy3);
      const spy4 = sinon.spy();
      this.provider.once('refresh_token.saved', spy4);

      await this.agent.post('/token')
        .send({
          client_id: 'client',
          resource: 'urn:wl:default',
          grant_type: 'refresh_token',
          refresh_token: rt.jti,
        })
        .type('form')
        .expect(200);

      expect(spy3.calledOnce).to.be.true;
      at = spy3.args[0][0];
      expect(at.aud).to.equal('urn:wl:default');

      expect(spy4.calledOnce).to.be.true;
      rt = spy4.args[0][0];
      expect(rt.resource).to.equal('urn:wl:default');
    });
  });

  describe('urn:openid:params:grant-type:ciba', () => {
    it('checks the policy and adds the resource', async function () {
      await this.agent.post('/backchannel')
        .send({
          client_id: 'client',
          resource: 'urn:not:allowed',
          scope: 'openid api:read',
          login_hint: 'accountId',
        })
        .type('form')
        .expect(400)
        .expect({
          error: 'invalid_target',
          error_description: 'resource indicator is missing, or unknown',
        });

      let auth_req_id;
      await this.agent.post('/backchannel')
        .send({
          client_id: 'client',
          resource: 'urn:wl:explicit',
          scope: 'openid api:read',
          login_hint: 'accountId',
        })
        .type('form')
        .expect(200)
        .expect(({ body }) => {
          ({ auth_req_id } = body);
        });

      const spy = sinon.spy();
      this.provider.once('access_token.saved', spy);
      this.provider.once('access_token.issued', spy);
      const spy2 = sinon.spy();
      this.provider.once('refresh_token.saved', spy2);

      await this.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'urn:openid:params:grant-type:ciba',
          auth_req_id,
          resource: 'urn:wl:explicit',
        })
        .type('form')
        .expect(200);

      expect(spy.calledOnce).to.be.true;
      let at = spy.args[0][0];
      expect(at.aud).to.equal('urn:wl:explicit');

      expect(spy2.calledOnce).to.be.true;
      let rt = spy2.args[0][0];
      expect(rt.resource).to.equal('urn:wl:explicit');

      const spy3 = sinon.spy();
      this.provider.once('access_token.saved', spy3);
      this.provider.once('access_token.issued', spy3);
      const spy4 = sinon.spy();
      this.provider.once('refresh_token.saved', spy4);

      await this.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'refresh_token',
          refresh_token: rt.jti,
          resource: 'urn:wl:explicit',
        })
        .type('form')
        .expect(200);

      expect(spy3.calledOnce).to.be.true;
      at = spy3.args[0][0];
      expect(at.aud).to.equal('urn:wl:explicit');

      expect(spy4.calledOnce).to.be.true;
      rt = spy4.args[0][0];
      expect(rt.resource).to.equal('urn:wl:explicit');
    });

    it('applies the default resource (when useGrantedResource returns true)', async function () {
      let auth_req_id;
      await this.agent.post('/backchannel')
        .send({
          client_id: 'client',
          scope: 'openid api:read',
          login_hint: 'accountId',
        })
        .type('form')
        .expect(200)
        .expect(({ body }) => {
          ({ auth_req_id } = body);
        });

      const spy = sinon.spy();
      this.provider.once('access_token.saved', spy);
      this.provider.once('access_token.issued', spy);
      const spy2 = sinon.spy();
      this.provider.once('refresh_token.saved', spy2);

      await this.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'urn:openid:params:grant-type:ciba',
          auth_req_id,
          usegranted: true,
        })
        .type('form')
        .expect(200);

      expect(spy.calledOnce).to.be.true;
      let at = spy.args[0][0];
      expect(at.aud).to.equal('urn:wl:default');

      expect(spy2.calledOnce).to.be.true;
      let rt = spy2.args[0][0];
      expect(rt.resource).to.equal('urn:wl:default');

      const spy3 = sinon.spy();
      this.provider.once('access_token.saved', spy3);
      this.provider.once('access_token.issued', spy3);
      const spy4 = sinon.spy();
      this.provider.once('refresh_token.saved', spy4);

      await this.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'refresh_token',
          refresh_token: rt.jti,
          usegranted: true,
        })
        .type('form')
        .expect(200);

      expect(spy3.calledOnce).to.be.true;
      at = spy3.args[0][0];
      expect(at.aud).to.equal('urn:wl:default');

      expect(spy4.calledOnce).to.be.true;
      rt = spy4.args[0][0];
      expect(rt.resource).to.equal('urn:wl:default');
    });

    it('issues access token for userinfo (when useGrantedResource returns false)', async function () {
      let auth_req_id;
      await this.agent.post('/backchannel')
        .send({
          client_id: 'client',
          scope: 'openid api:read',
          login_hint: 'accountId',
        })
        .type('form')
        .expect(200)
        .expect(({ body }) => {
          ({ auth_req_id } = body);
        });

      const spy = sinon.spy();
      this.provider.once('access_token.saved', spy);
      this.provider.once('access_token.issued', spy);
      const spy2 = sinon.spy();
      this.provider.once('refresh_token.saved', spy2);

      await this.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'urn:openid:params:grant-type:ciba',
          auth_req_id,
        })
        .type('form')
        .expect(200);

      expect(spy.calledOnce).to.be.true;
      let at = spy.args[0][0];
      expect(at.aud).to.equal(undefined);

      expect(spy2.calledOnce).to.be.true;
      let rt = spy2.args[0][0];
      expect(rt.resource).to.equal('urn:wl:default');

      const spy3 = sinon.spy();
      this.provider.once('access_token.saved', spy3);
      this.provider.once('access_token.issued', spy3);
      const spy4 = sinon.spy();
      this.provider.once('refresh_token.saved', spy4);

      await this.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'refresh_token',
          refresh_token: rt.jti,
        })
        .type('form')
        .expect(200);

      expect(spy3.calledOnce).to.be.true;
      at = spy3.args[0][0];
      expect(at.aud).to.equal(undefined);

      expect(spy4.calledOnce).to.be.true;
      rt = spy4.args[0][0];
      expect(rt.resource).to.equal('urn:wl:default');
    });
  });

  describe('userinfo', () => {
    it('allows userinfo for audience-less tokens', async function () {
      const at = new this.provider.AccessToken({
        accountId: this.loggedInAccountId,
        grantId: this.getGrantId(),
        client: await this.provider.Client.find('client'),
        scope: 'openid api:read',
        aud: undefined,
      });

      const bearer = await at.save();

      return this.agent.get('/me')
        .auth(bearer, { type: 'bearer' })
        .expect(200);
    });

    it('fails userinfo for string userinfo url tokens', async function () {
      const at = new this.provider.AccessToken({
        accountId: this.loggedInAccountId,
        grantId: this.getGrantId(),
        client: await this.provider.Client.find('client'),
        scope: 'openid api:read',
        aud: 'urn:foo:bar',
      });

      const bearer = await at.save();

      const spy = sinon.spy();
      this.provider.once('userinfo.error', spy);

      await this.agent.get('/me')
        .auth(bearer, { type: 'bearer' })
        .expect(401)
        .expect({ error: 'invalid_token', error_description: 'invalid token provided' });

      expect(spy).to.have.property('calledOnce', true);
      expect(spy.args[0][1]).to.have.property('error_detail', 'token audience prevents accessing the userinfo endpoint');
    });

    [{}, false, 1].forEach((aud, i, { length }) => {
      it(`fails on various invalid aud values ${i + 1}/${length}`, async function () {
        const at = new this.provider.AccessToken({
          accountId: this.loggedInAccountId,
          grantId: this.getGrantId(),
          client: await this.provider.Client.find('client'),
          scope: 'openid api:read',
          aud,
        });

        const bearer = await at.save();

        const spy = sinon.spy();
        this.provider.once('userinfo.error', spy);

        await this.agent.get('/me')
          .auth(bearer, { type: 'bearer' })
          .expect(401)
          .expect({ error: 'invalid_token', error_description: 'invalid token provided' });

        expect(spy).to.have.property('calledOnce', true);
        expect(spy.args[0][1]).to.have.property('error_detail', 'token audience prevents accessing the userinfo endpoint');
      });
    });
  });
});
