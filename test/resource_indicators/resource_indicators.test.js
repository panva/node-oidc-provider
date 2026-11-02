import { describe, it, before, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import sinon from 'sinon';
import { decodeJwt } from 'jose';

import bootstrap from '../test_helper.js';
import { defaults } from '../../lib/helpers/defaults.js';
import instance from '../../lib/helpers/weak_cache.js';

const { features: { resourceIndicators } } = defaults;

describe('features.resourceIndicators defaults', () => {
  it('defaultResource', { timeout: 3000 }, async () => {
    assert.equal(await resourceIndicators.defaultResource(), undefined);
    assert.deepEqual(await resourceIndicators.defaultResource(undefined, undefined, ['urn:example:rs']), ['urn:example:rs']);
  });

  it('getResourceServerInfo', { timeout: 3000 }, () => assert.rejects(resourceIndicators.getResourceServerInfo(), (err) => {
    assert.equal(err.message, 'invalid_target');
    assert.equal(err.error_description, 'resource indicator is missing, or unknown');
    return true;
  }));
});

describe('features.resourceIndicators', () => {
  const fixture1 = {};

  before(bootstrap(import.meta.url, fixture1), { timeout: 3000 });
  afterEach(() => {
    fixture1.provider.removeAllListeners();
  }, { timeout: 3000 });
  before(() => fixture1.login({
      resources: {
        'urn:wl:default': 'api:read api:write',
        'urn:wl:explicit': 'api:read api:write',
      },
    }), { timeout: 3000 });

  describe('Resource Server scope changes before token issuance', () => {
    const fixture2 = Object.create(fixture1);

    const sandbox = sinon.createSandbox();
    const resource = 'urn:wl:explicit';
    const scope = 'api:read api:write';
    const grantTypes = {
      authorization_code: async function () {
        const auth = new this.AuthorizationRequest({ response_type: 'code', resource, scope });
        const response = await this.wrap({ route: '/auth', verb: 'get', auth })
          .expect(303)
          .expect(auth.validatePresence(['code', 'state']));

        return {
          code: new URL(response.headers.location).searchParams.get('code'),
          code_verifier: auth.code_verifier,
        };
      },
      'urn:ietf:params:oauth:grant-type:device_code': async function () {
        const { body: { user_code, device_code } } = await this.agent.post('/device/auth')
          .send({ client_id: 'client', resource, scope })
          .type('form')
          .expect(200);

        this.getSession().state = { secret: 'scope-change' };
        await this.agent.post('/device')
          .send({ user_code, xsrf: 'scope-change', confirm: true })
          .type('form')
          .expect(200);

        return { device_code };
      },
      'urn:openid:params:grant-type:ciba': async function () {
        sandbox.stub(instance(this.provider).features.ciba, 'triggerAuthenticationDevice')
          .callsFake(async (_ctx, request) => {
            const grant = new this.provider.Grant({
              clientId: request.clientId, accountId: request.accountId,
            });
            grant.addOIDCScope('openid');
            grant.addResourceScope(resource, scope);
            await grant.save();
            return this.provider.backchannelResult(request, grant.jti);
          });

        const { body: { auth_req_id } } = await this.agent.post('/backchannel')
          .send({
            client_id: 'client', resource, scope: `openid ${scope}`, login_hint: 'accountId',
          })
          .type('form')
          .expect(200);

        return { auth_req_id };
      },
    };

    afterEach(() => sandbox.restore(), { timeout: 3000 });

    for (const [grant_type, authorize] of Object.entries(grantTypes)) {
      for (const accessTokenFormat of ['opaque', 'jwt']) {
        for (const [policy, currentScope, expectedScope] of [
          ['unchanged', scope, scope],
          ['narrowed', 'api:read api:admin', 'api:read'],
          ['removed', 'api:admin', ''],
        ]) {
          it(`${grant_type} applies ${policy} scopes to ${accessTokenFormat} access tokens`, { timeout: 3000 }, async () => {
            let resourceScope = scope;
            sandbox.stub(instance(fixture2.provider).features.resourceIndicators, 'getResourceServerInfo')
              .callsFake(() => ({ scope: resourceScope, audience: resource, accessTokenFormat }));

            const parameters = await authorize.call(fixture2);
            resourceScope = currentScope;

            const issued = sandbox.spy();
            fixture2.provider.once('access_token.saved', issued);
            fixture2.provider.once('access_token.issued', issued);

            const { body } = await fixture2.agent.post('/token')
              .send({ client_id: 'client', grant_type, resource, ...parameters })
              .type('form')
              .expect(200);

            ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, expectedScope); })(body);
            assert.equal(issued.calledOnce, true);
            ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, expectedScope); })(issued.firstCall.args[0]);
            if (accessTokenFormat === 'jwt') {
              const payload = decodeJwt(body.access_token);
              if (expectedScope) {
                ((actual) => { assert.ok('scope' in Object(actual)); assert.equal(actual.scope, expectedScope); })(payload);
              } else {
                assert.ok(!('scope' in Object(payload)));
              }
            }
          });
        }
      }
    }
  });

  describe('resource validations', () => {
    const fixture3 = Object.create(fixture1);

    it('must be a URI', { timeout: 3000 }, () => fixture3.agent.post('/token')
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
        }));

    it('must not contain a fragment', { timeout: 3000 }, () => fixture3.agent.post('/token')
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
        }));
  });

  ['get', 'post'].forEach((verb) => {
    describe(`${verb} response_type includes token`, () => {
      const fixture4 = Object.create(fixture1);

      const response_type = 'id_token token';

      it('checks the policy and adds the resource', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture4.provider.once('access_token.saved', spy);
        fixture4.provider.once('access_token.issued', spy);

        const auth = new fixture4.AuthorizationRequest({
          response_type,
          resource: 'urn:not:allowed',
          scope: 'openid api:read',
        });

        await fixture4.wrap({ route: '/auth', verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_target'))
          .expect(auth.validateErrorDescription('resource indicator is missing, or unknown'));

        auth.resource = 'urn:wl:explicit';
        await fixture4.wrap({ route: '/auth', verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token', 'state', 'access_token', 'expires_in', 'token_type', 'scope']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);

        assert.equal(spy.calledOnce, true);
        const token = spy.args[0][0];
        assert.equal(token.aud, 'urn:wl:explicit');
      });

      it('applies the default resource', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture4.provider.once('access_token.saved', spy);
        fixture4.provider.once('access_token.issued', spy);

        const auth = new fixture4.AuthorizationRequest({
          response_type,
          scope: 'openid api:read',
        });

        await fixture4.wrap({ route: '/auth', verb, auth })
          .expect(303)
          .expect(auth.validateFragment)
          .expect(auth.validatePresence(['id_token', 'state', 'access_token', 'expires_in', 'token_type', 'scope']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);

        assert.equal(spy.calledOnce, true);
        const token = spy.args[0][0];
        assert.equal(token.aud, 'urn:wl:default');
      });
    });

    describe(`${verb} response_type includes code`, () => {
      const fixture5 = Object.create(fixture1);

      const response_type = 'code';

      it('checks the policy and adds the resource', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture5.provider.once('authorization_code.saved', spy);

        const auth = new fixture5.AuthorizationRequest({
          response_type,
          resource: 'urn:not:allowed',
          scope: 'api:read',
        });

        await fixture5.wrap({ route: '/auth', verb, auth })
          .expect(303)
          .expect(auth.validatePresence(['error', 'error_description', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation)
          .expect(auth.validateError('invalid_target'))
          .expect(auth.validateErrorDescription('resource indicator is missing, or unknown'));

        auth.resource = 'urn:wl:explicit';
        await fixture5.wrap({ route: '/auth', verb, auth })
          .expect(303)
          .expect(auth.validatePresence(['code', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);

        assert.equal(spy.calledOnce, true);
        const code = spy.args[0][0];
        assert.equal(code.resource, 'urn:wl:explicit');

        const spy2 = sinon.spy();
        fixture5.provider.once('access_token.saved', spy2);
        fixture5.provider.once('access_token.issued', spy2);
        const spy3 = sinon.spy();
        fixture5.provider.once('refresh_token.saved', spy3);

        await fixture5.agent.post('/token')
          .send({
            client_id: 'client',
            grant_type: 'authorization_code',
            code_verifier: auth.code_verifier,
            code: code.jti,
          })
          .type('form')
          .expect(200);

        assert.equal(spy2.calledOnce, true);
        let at = spy2.args[0][0];
        assert.equal(at.aud, 'urn:wl:explicit');

        assert.equal(spy3.calledOnce, true);
        let rt = spy3.args[0][0];
        assert.equal(rt.resource, 'urn:wl:explicit');

        const spy4 = sinon.spy();
        fixture5.provider.once('access_token.saved', spy4);
        fixture5.provider.once('access_token.issued', spy4);
        const spy5 = sinon.spy();
        fixture5.provider.once('refresh_token.saved', spy5);

        await fixture5.agent.post('/token')
          .send({
            client_id: 'client',
            grant_type: 'refresh_token',
            refresh_token: rt.jti,
          })
          .type('form')
          .expect(200);

        assert.equal(spy4.calledOnce, true);
        at = spy4.args[0][0];
        assert.equal(at.aud, 'urn:wl:explicit');

        assert.equal(spy5.calledOnce, true);
        rt = spy5.args[0][0];
        assert.equal(rt.resource, 'urn:wl:explicit');
      });

      it('applies the default resource', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture5.provider.once('authorization_code.saved', spy);

        const auth = new fixture5.AuthorizationRequest({
          response_type,
          scope: 'api:read',
        });

        await fixture5.wrap({ route: '/auth', verb, auth })
          .expect(303)
          .expect(auth.validatePresence(['code', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);

        assert.equal(spy.calledOnce, true);
        const code = spy.args[0][0];
        assert.equal(code.resource, 'urn:wl:default');

        const spy2 = sinon.spy();
        fixture5.provider.once('access_token.saved', spy2);
        fixture5.provider.once('access_token.issued', spy2);
        const spy3 = sinon.spy();
        fixture5.provider.once('refresh_token.saved', spy3);

        await fixture5.agent.post('/token')
          .send({
            client_id: 'client',
            grant_type: 'authorization_code',
            code_verifier: auth.code_verifier,
            code: code.jti,
          })
          .type('form')
          .expect(200);

        assert.equal(spy2.calledOnce, true);
        let at = spy2.args[0][0];
        assert.equal(at.aud, 'urn:wl:default');

        assert.equal(spy3.calledOnce, true);
        let rt = spy3.args[0][0];
        assert.equal(rt.resource, 'urn:wl:default');

        const spy4 = sinon.spy();
        fixture5.provider.once('access_token.saved', spy4);
        fixture5.provider.once('access_token.issued', spy4);
        const spy5 = sinon.spy();
        fixture5.provider.once('refresh_token.saved', spy5);

        await fixture5.agent.post('/token')
          .send({
            client_id: 'client',
            grant_type: 'refresh_token',
            refresh_token: rt.jti,
          })
          .type('form')
          .expect(200);

        assert.equal(spy4.calledOnce, true);
        at = spy4.args[0][0];
        assert.equal(at.aud, 'urn:wl:default');

        assert.equal(spy5.calledOnce, true);
        rt = spy5.args[0][0];
        assert.equal(rt.resource, 'urn:wl:default');
      });

      it('applies the default resource (when useGrantedResource returns true)', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture5.provider.once('authorization_code.saved', spy);

        const auth = new fixture5.AuthorizationRequest({
          response_type,
          scope: 'openid api:read',
        });

        await fixture5.wrap({ route: '/auth', verb, auth })
          .expect(303)
          .expect(auth.validatePresence(['code', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);

        assert.equal(spy.calledOnce, true);
        const code = spy.args[0][0];
        assert.equal(code.resource, 'urn:wl:default');

        const spy2 = sinon.spy();
        fixture5.provider.once('access_token.saved', spy2);
        fixture5.provider.once('access_token.issued', spy2);
        const spy3 = sinon.spy();
        fixture5.provider.once('refresh_token.saved', spy3);

        await fixture5.agent.post('/token')
          .send({
            client_id: 'client',
            grant_type: 'authorization_code',
            code_verifier: auth.code_verifier,
            code: code.jti,
            usegranted: true,
          })
          .type('form')
          .expect(200);

        assert.equal(spy2.calledOnce, true);
        let at = spy2.args[0][0];
        assert.equal(at.aud, 'urn:wl:default');

        assert.equal(spy3.calledOnce, true);
        let rt = spy3.args[0][0];
        assert.equal(rt.resource, 'urn:wl:default');

        const spy4 = sinon.spy();
        fixture5.provider.once('access_token.saved', spy4);
        fixture5.provider.once('access_token.issued', spy4);
        const spy5 = sinon.spy();
        fixture5.provider.once('refresh_token.saved', spy5);

        await fixture5.agent.post('/token')
          .send({
            client_id: 'client',
            grant_type: 'refresh_token',
            refresh_token: rt.jti,
            usegranted: true,
          })
          .type('form')
          .expect(200);

        assert.equal(spy4.calledOnce, true);
        at = spy4.args[0][0];
        assert.equal(at.aud, 'urn:wl:default');

        assert.equal(spy5.calledOnce, true);
        rt = spy5.args[0][0];
        assert.equal(rt.resource, 'urn:wl:default');
      });

      it('applies the explicit resource', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture5.provider.once('authorization_code.saved', spy);

        const auth = new fixture5.AuthorizationRequest({
          response_type,
          scope: 'openid api:read',
        });

        await fixture5.wrap({ route: '/auth', verb, auth })
          .expect(303)
          .expect(auth.validatePresence(['code', 'state']))
          .expect(auth.validateState)
          .expect(auth.validateClientLocation);

        assert.equal(spy.calledOnce, true);
        const code = spy.args[0][0];
        assert.equal(code.resource, 'urn:wl:default');

        const spy2 = sinon.spy();
        fixture5.provider.once('access_token.saved', spy2);
        fixture5.provider.once('access_token.issued', spy2);
        const spy3 = sinon.spy();
        fixture5.provider.once('refresh_token.saved', spy3);

        await fixture5.agent.post('/token')
          .send({
            client_id: 'client',
            grant_type: 'authorization_code',
            code_verifier: auth.code_verifier,
            code: code.jti,
            resource: 'urn:wl:default',
          })
          .type('form')
          .expect(200);

        assert.equal(spy2.calledOnce, true);
        let at = spy2.args[0][0];
        assert.equal(at.aud, 'urn:wl:default');

        assert.equal(spy3.calledOnce, true);
        let rt = spy3.args[0][0];
        assert.equal(rt.resource, 'urn:wl:default');

        const spy4 = sinon.spy();
        fixture5.provider.once('access_token.saved', spy4);
        fixture5.provider.once('access_token.issued', spy4);
        const spy5 = sinon.spy();
        fixture5.provider.once('refresh_token.saved', spy5);

        await fixture5.agent.post('/token')
          .send({
            client_id: 'client',
            grant_type: 'refresh_token',
            refresh_token: rt.jti,
            resource: 'urn:wl:default',
          })
          .type('form')
          .expect(200);

        assert.equal(spy4.calledOnce, true);
        at = spy4.args[0][0];
        assert.equal(at.aud, 'urn:wl:default');

        assert.equal(spy5.calledOnce, true);
        rt = spy5.args[0][0];
        assert.equal(rt.resource, 'urn:wl:default');
      });
    });
  });

  describe('urn:ietf:params:oauth:grant-type:device_code', () => {
    const fixture6 = Object.create(fixture1);

    it('checks the policy and adds the resource', { timeout: 3000 }, async () => {
      await fixture6.agent.post('/device/auth')
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
      await fixture6.agent.post('/device/auth')
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

      fixture6.getSession().state = { secret: 'foo' };

      await fixture6.agent.post('/device')
        .send({
          user_code,
          xsrf: 'foo',
          confirm: true,
        })
        .type('form')
        .expect(200);

      const spy = sinon.spy();
      fixture6.provider.once('access_token.saved', spy);
      fixture6.provider.once('access_token.issued', spy);
      const spy2 = sinon.spy();
      fixture6.provider.once('refresh_token.saved', spy2);

      await fixture6.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code,
        })
        .type('form')
        .expect(200);

      assert.equal(spy.calledOnce, true);
      let at = spy.args[0][0];
      assert.equal(at.aud, 'urn:wl:explicit');

      assert.equal(spy2.calledOnce, true);
      let rt = spy2.args[0][0];
      assert.equal(rt.resource, 'urn:wl:explicit');

      const spy3 = sinon.spy();
      fixture6.provider.once('access_token.saved', spy3);
      fixture6.provider.once('access_token.issued', spy3);
      const spy4 = sinon.spy();
      fixture6.provider.once('refresh_token.saved', spy4);

      await fixture6.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'refresh_token',
          refresh_token: rt.jti,
        })
        .type('form')
        .expect(200);

      assert.equal(spy3.calledOnce, true);
      at = spy3.args[0][0];
      assert.equal(at.aud, 'urn:wl:explicit');

      assert.equal(spy4.calledOnce, true);
      rt = spy4.args[0][0];
      assert.equal(rt.resource, 'urn:wl:explicit');
    });

    it('applies the default resource', { timeout: 3000 }, async () => {
      let user_code;
      let device_code;
      await fixture6.agent.post('/device/auth')
        .send({
          client_id: 'client',
          scope: 'api:read',
        })
        .type('form')
        .expect(200)
        .expect(({ body }) => {
          ({ user_code, device_code } = body);
        });

      fixture6.getSession().state = { secret: 'foo' };

      await fixture6.agent.post('/device')
        .send({
          user_code,
          xsrf: 'foo',
          confirm: true,
        })
        .type('form')
        .expect(200);

      const spy = sinon.spy();
      fixture6.provider.once('access_token.saved', spy);
      fixture6.provider.once('access_token.issued', spy);
      const spy2 = sinon.spy();
      fixture6.provider.once('refresh_token.saved', spy2);

      await fixture6.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code,
        })
        .type('form')
        .expect(200);

      assert.equal(spy.calledOnce, true);
      let at = spy.args[0][0];
      assert.equal(at.aud, 'urn:wl:default');

      assert.equal(spy2.calledOnce, true);
      let rt = spy2.args[0][0];
      assert.equal(rt.resource, 'urn:wl:default');

      const spy3 = sinon.spy();
      fixture6.provider.once('access_token.saved', spy3);
      fixture6.provider.once('access_token.issued', spy3);
      const spy4 = sinon.spy();
      fixture6.provider.once('refresh_token.saved', spy4);

      await fixture6.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'refresh_token',
          refresh_token: rt.jti,
        })
        .type('form')
        .expect(200);

      assert.equal(spy3.calledOnce, true);
      at = spy3.args[0][0];
      assert.equal(at.aud, 'urn:wl:default');

      assert.equal(spy4.calledOnce, true);
      rt = spy4.args[0][0];
      assert.equal(rt.resource, 'urn:wl:default');
    });

    it('applies the default resource (when useGrantedResource returns true)', { timeout: 3000 }, async () => {
      let user_code;
      let device_code;
      await fixture6.agent.post('/device/auth')
        .send({
          client_id: 'client',
          scope: 'openid api:read',
        })
        .type('form')
        .expect(200)
        .expect(({ body }) => {
          ({ user_code, device_code } = body);
        });

      fixture6.getSession().state = { secret: 'foo' };

      await fixture6.agent.post('/device')
        .send({
          user_code,
          xsrf: 'foo',
          confirm: true,
        })
        .type('form')
        .expect(200);

      const spy = sinon.spy();
      fixture6.provider.once('access_token.saved', spy);
      fixture6.provider.once('access_token.issued', spy);
      const spy2 = sinon.spy();
      fixture6.provider.once('refresh_token.saved', spy2);

      await fixture6.agent.post('/token')
        .send({
          client_id: 'client',
          usegranted: true,
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code,
        })
        .type('form')
        .expect(200);

      assert.equal(spy.calledOnce, true);
      let at = spy.args[0][0];
      assert.equal(at.aud, 'urn:wl:default');

      assert.equal(spy2.calledOnce, true);
      let rt = spy2.args[0][0];
      assert.equal(rt.resource, 'urn:wl:default');

      const spy3 = sinon.spy();
      fixture6.provider.once('access_token.saved', spy3);
      fixture6.provider.once('access_token.issued', spy3);
      const spy4 = sinon.spy();
      fixture6.provider.once('refresh_token.saved', spy4);

      await fixture6.agent.post('/token')
        .send({
          client_id: 'client',
          usegranted: true,
          grant_type: 'refresh_token',
          refresh_token: rt.jti,
        })
        .type('form')
        .expect(200);

      assert.equal(spy3.calledOnce, true);
      at = spy3.args[0][0];
      assert.equal(at.aud, 'urn:wl:default');

      assert.equal(spy4.calledOnce, true);
      rt = spy4.args[0][0];
      assert.equal(rt.resource, 'urn:wl:default');
    });

    it('applies the explicit resource', { timeout: 3000 }, async () => {
      let user_code;
      let device_code;
      await fixture6.agent.post('/device/auth')
        .send({
          client_id: 'client',
          scope: 'openid api:read',
        })
        .type('form')
        .expect(200)
        .expect(({ body }) => {
          ({ user_code, device_code } = body);
        });

      fixture6.getSession().state = { secret: 'foo' };

      await fixture6.agent.post('/device')
        .send({
          user_code,
          xsrf: 'foo',
          confirm: true,
        })
        .type('form')
        .expect(200);

      const spy = sinon.spy();
      fixture6.provider.once('access_token.saved', spy);
      fixture6.provider.once('access_token.issued', spy);
      const spy2 = sinon.spy();
      fixture6.provider.once('refresh_token.saved', spy2);

      await fixture6.agent.post('/token')
        .send({
          client_id: 'client',
          resource: 'urn:wl:default',
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code,
        })
        .type('form')
        .expect(200);

      assert.equal(spy.calledOnce, true);
      let at = spy.args[0][0];
      assert.equal(at.aud, 'urn:wl:default');

      assert.equal(spy2.calledOnce, true);
      let rt = spy2.args[0][0];
      assert.equal(rt.resource, 'urn:wl:default');

      const spy3 = sinon.spy();
      fixture6.provider.once('access_token.saved', spy3);
      fixture6.provider.once('access_token.issued', spy3);
      const spy4 = sinon.spy();
      fixture6.provider.once('refresh_token.saved', spy4);

      await fixture6.agent.post('/token')
        .send({
          client_id: 'client',
          resource: 'urn:wl:default',
          grant_type: 'refresh_token',
          refresh_token: rt.jti,
        })
        .type('form')
        .expect(200);

      assert.equal(spy3.calledOnce, true);
      at = spy3.args[0][0];
      assert.equal(at.aud, 'urn:wl:default');

      assert.equal(spy4.calledOnce, true);
      rt = spy4.args[0][0];
      assert.equal(rt.resource, 'urn:wl:default');
    });
  });

  describe('urn:openid:params:grant-type:ciba', () => {
    const fixture7 = Object.create(fixture1);

    it('checks the policy and adds the resource', { timeout: 3000 }, async () => {
      await fixture7.agent.post('/backchannel')
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
      await fixture7.agent.post('/backchannel')
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
      fixture7.provider.once('access_token.saved', spy);
      fixture7.provider.once('access_token.issued', spy);
      const spy2 = sinon.spy();
      fixture7.provider.once('refresh_token.saved', spy2);

      await fixture7.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'urn:openid:params:grant-type:ciba',
          auth_req_id,
          resource: 'urn:wl:explicit',
        })
        .type('form')
        .expect(200);

      assert.equal(spy.calledOnce, true);
      let at = spy.args[0][0];
      assert.equal(at.aud, 'urn:wl:explicit');

      assert.equal(spy2.calledOnce, true);
      let rt = spy2.args[0][0];
      assert.equal(rt.resource, 'urn:wl:explicit');

      const spy3 = sinon.spy();
      fixture7.provider.once('access_token.saved', spy3);
      fixture7.provider.once('access_token.issued', spy3);
      const spy4 = sinon.spy();
      fixture7.provider.once('refresh_token.saved', spy4);

      await fixture7.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'refresh_token',
          refresh_token: rt.jti,
          resource: 'urn:wl:explicit',
        })
        .type('form')
        .expect(200);

      assert.equal(spy3.calledOnce, true);
      at = spy3.args[0][0];
      assert.equal(at.aud, 'urn:wl:explicit');

      assert.equal(spy4.calledOnce, true);
      rt = spy4.args[0][0];
      assert.equal(rt.resource, 'urn:wl:explicit');
    });

    it('applies the default resource (when useGrantedResource returns true)', { timeout: 3000 }, async () => {
      let auth_req_id;
      await fixture7.agent.post('/backchannel')
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
      fixture7.provider.once('access_token.saved', spy);
      fixture7.provider.once('access_token.issued', spy);
      const spy2 = sinon.spy();
      fixture7.provider.once('refresh_token.saved', spy2);

      await fixture7.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'urn:openid:params:grant-type:ciba',
          auth_req_id,
          usegranted: true,
        })
        .type('form')
        .expect(200);

      assert.equal(spy.calledOnce, true);
      let at = spy.args[0][0];
      assert.equal(at.aud, 'urn:wl:default');

      assert.equal(spy2.calledOnce, true);
      let rt = spy2.args[0][0];
      assert.equal(rt.resource, 'urn:wl:default');

      const spy3 = sinon.spy();
      fixture7.provider.once('access_token.saved', spy3);
      fixture7.provider.once('access_token.issued', spy3);
      const spy4 = sinon.spy();
      fixture7.provider.once('refresh_token.saved', spy4);

      await fixture7.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'refresh_token',
          refresh_token: rt.jti,
          usegranted: true,
        })
        .type('form')
        .expect(200);

      assert.equal(spy3.calledOnce, true);
      at = spy3.args[0][0];
      assert.equal(at.aud, 'urn:wl:default');

      assert.equal(spy4.calledOnce, true);
      rt = spy4.args[0][0];
      assert.equal(rt.resource, 'urn:wl:default');
    });

    it('issues access token for userinfo (when useGrantedResource returns false)', { timeout: 3000 }, async () => {
      let auth_req_id;
      await fixture7.agent.post('/backchannel')
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
      fixture7.provider.once('access_token.saved', spy);
      fixture7.provider.once('access_token.issued', spy);
      const spy2 = sinon.spy();
      fixture7.provider.once('refresh_token.saved', spy2);

      await fixture7.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'urn:openid:params:grant-type:ciba',
          auth_req_id,
        })
        .type('form')
        .expect(200);

      assert.equal(spy.calledOnce, true);
      let at = spy.args[0][0];
      assert.equal(at.aud, undefined);

      assert.equal(spy2.calledOnce, true);
      let rt = spy2.args[0][0];
      assert.equal(rt.resource, 'urn:wl:default');

      const spy3 = sinon.spy();
      fixture7.provider.once('access_token.saved', spy3);
      fixture7.provider.once('access_token.issued', spy3);
      const spy4 = sinon.spy();
      fixture7.provider.once('refresh_token.saved', spy4);

      await fixture7.agent.post('/token')
        .send({
          client_id: 'client',
          grant_type: 'refresh_token',
          refresh_token: rt.jti,
        })
        .type('form')
        .expect(200);

      assert.equal(spy3.calledOnce, true);
      at = spy3.args[0][0];
      assert.equal(at.aud, undefined);

      assert.equal(spy4.calledOnce, true);
      rt = spy4.args[0][0];
      assert.equal(rt.resource, 'urn:wl:default');
    });
  });

  describe('userinfo', () => {
    const fixture8 = Object.create(fixture1);

    it('allows userinfo for audience-less tokens', { timeout: 3000 }, async () => {
      const at = new fixture8.provider.AccessToken({
        accountId: fixture8.loggedInAccountId,
        grantId: fixture8.getGrantId(),
        client: await fixture8.provider.Client.find('client'),
        scope: 'openid api:read',
        aud: undefined,
      });

      const bearer = await at.save();

      return fixture8.agent.get('/me')
        .auth(bearer, { type: 'bearer' })
        .expect(200);
    });

    it('fails userinfo for string userinfo url tokens', { timeout: 3000 }, async () => {
      const at = new fixture8.provider.AccessToken({
        accountId: fixture8.loggedInAccountId,
        grantId: fixture8.getGrantId(),
        client: await fixture8.provider.Client.find('client'),
        scope: 'openid api:read',
        aud: 'urn:foo:bar',
      });

      const bearer = await at.save();

      const spy = sinon.spy();
      fixture8.provider.once('userinfo.error', spy);

      await fixture8.agent.get('/me')
        .auth(bearer, { type: 'bearer' })
        .expect(401)
        .expect({ error: 'invalid_token', error_description: 'invalid token provided' });

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
      ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'token audience prevents accessing the userinfo endpoint'); })(spy.args[0][1]);
    });

    [{}, false, 1].forEach((aud, i, { length }) => {
      it(`fails on various invalid aud values ${i + 1}/${length}`, { timeout: 3000 }, async () => {
        const at = new fixture8.provider.AccessToken({
          accountId: fixture8.loggedInAccountId,
          grantId: fixture8.getGrantId(),
          client: await fixture8.provider.Client.find('client'),
          scope: 'openid api:read',
          aud,
        });

        const bearer = await at.save();

        const spy = sinon.spy();
        fixture8.provider.once('userinfo.error', spy);

        await fixture8.agent.get('/me')
          .auth(bearer, { type: 'bearer' })
          .expect(401)
          .expect({ error: 'invalid_token', error_description: 'invalid token provided' });

        ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
        ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'access token not found'); })(spy.args[0][1]);
      });
    });
  });
});
