import { describe, before, after, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import * as url from 'node:url';

import sinon from 'sinon';

import bootstrap, { skipConsent } from '../test_helper.js';

const crt = new X509Certificate(readFileSync('./test/jwks/client.crt', { encoding: 'ascii' }));
const expectedS256 = 'A4DtL2JmUMhAsvJj5tKyn64SqzmuXbMrJa0n761y5v0';

describe('features.mTLS.certificateBoundAccessTokens', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });
  before(() => fixture.login(), { timeout: 3000 });
  after(() => fixture.logout(), { timeout: 3000 });

  describe('discovery', () => {
    const fixture1 = Object.create(fixture);

    it('extends discovery', { timeout: 3000 }, () => fixture1.agent.get('/.well-known/openid-configuration')
        .expect(200)
        .expect((response) => {
          ((actual) => { assert.ok('tls_client_certificate_bound_access_tokens' in Object(actual)); assert.equal(actual.tls_client_certificate_bound_access_tokens, true); })(response.body);
        }));
  });

  describe('userinfo', () => {
    const fixture2 = Object.create(fixture);

    it('acts like an RS checking the thumbprint now', { timeout: 3000 }, async () => {
      const at = new fixture2.provider.AccessToken({
        grantId: fixture2.getGrantId('client'),
        accountId: fixture2.loggedInAccountId,
        client: await fixture2.provider.Client.find('client'),
        scope: 'openid',
      });
      at.setThumbprint('x5t', crt);

      ((actual) => { assert.throws(actual, (error) => { assert.ok('error_description' in Object(error)); assert.equal(error.error_description, 'multiple proof-of-possession mechanisms are not allowed'); return true; }); })(() => at.setThumbprint('jkt', 'foo'));

      const bearer = await at.save();
      const spy = sinon.spy();
      fixture2.provider.once('userinfo.error', spy);

      await fixture2.agent.get('/me')
        .auth(bearer, { type: 'bearer' })
        .expect(401);

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
      ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'failed x5t#S256 verification'); })(spy.args[0][1]);

      await fixture2.agent.get('/me')
        .auth(bearer, { type: 'bearer' })
        .set('x-ssl-client-cert', 'foobar')
        .expect(401);

      await fixture2.agent.get('/me')
        .auth(bearer, { type: 'bearer' })
        .set('x-ssl-client-cert', crt.raw.toString('base64'))
        .expect(200);
    });
  });

  describe('introspection', () => {
    const fixture3 = Object.create(fixture);

    it('exposes cnf now', { timeout: 3000 }, async () => {
      const at = new fixture3.provider.AccessToken({
        grantId: fixture3.getGrantId('client'),
        accountId: fixture3.loggedInAccountId,
        client: await fixture3.provider.Client.find('client'),
        scope: 'openid',
      });
      at.setThumbprint('x5t', crt);

      const token = await at.save();

      await fixture3.agent.post('/token/introspection')
        .auth('client', 'secret')
        .send({ token })
        .type('form')
        .expect(200)
        .expect(({ body }) => {
          assert.ok('cnf' in Object(body));
          ((actual) => { assert.ok('token_type' in Object(actual)); assert.equal(actual.token_type, 'Bearer'); })(body);
          assert.ok('x5t#S256' in Object(body.cnf));
        });
    });
  });

  describe('urn:ietf:params:oauth:grant-type:device_code', () => {
    const fixture4 = Object.create(fixture);

    before(() => fixture4.login({ scope: 'openid offline_access' }), { timeout: 3000 });
    beforeEach(async () => {
      await fixture4.agent.post('/device/auth')
        .auth('client', 'secret')
        .send({ scope: 'openid' })
        .type('form')
        .expect(200)
        .expect(({ body: { device_code: dc } }) => {
          fixture4.dc = dc;
        });

      fixture4.TestAdapter.for('DeviceCode').syncUpdate(fixture4.getTokenJti(fixture4.dc), {
        grantId: fixture4.getGrantId('client'),
        scope: 'openid offline_access',
        accountId: fixture4.loggedInAccountId,
      });
    }, { timeout: 3000 });

    it('binds the access token to the certificate', { timeout: 3000 }, async () => {
      const spy = sinon.spy();
      fixture4.provider.once('grant.success', spy);

      await fixture4.agent.post('/token')
        .auth('client', 'secret')
        .send({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: fixture4.dc,
        })
        .type('form')
        .set('x-ssl-client-cert', crt.raw.toString('base64'))
        .expect(200);

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
      const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
      ((actual) => { assert.ok('x5t#S256' in Object(actual)); assert.equal(actual['x5t#S256'], expectedS256); })(AccessToken);
      assert.ok(!('x5t#S256' in Object(RefreshToken)));
    });

    it('verifies the request made with mutual-TLS', { timeout: 3000 }, async () => {
      const spy = sinon.spy();
      fixture4.provider.once('grant.error', spy);

      await fixture4.agent.post('/token')
        .auth('client', 'secret')
        .send({
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: fixture4.dc,
        })
        .type('form')
        .expect(400)
        .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
      ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'mutual TLS client certificate not provided'); })(spy.args[0][1]);
    });

    it('binds the refresh token to the certificate for public clients', { timeout: 3000 }, async () => {
      const spy = sinon.spy();
      fixture4.provider.once('grant.success', spy);

      // changes the code to client-none and
      fixture4.TestAdapter.for('DeviceCode').syncUpdate(fixture4.getTokenJti(fixture4.dc), {
        clientId: 'client-none',
        grantId: fixture4.getGrantId('client-none'),
        accountId: fixture4.loggedInAccountId,
      });

      await fixture4.agent.post('/token')
        .send({
          client_id: 'client-none',
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
          device_code: fixture4.dc,
        })
        .type('form')
        .set('x-ssl-client-cert', crt.raw.toString('base64'))
        .expect(200);

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
      const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
      ((actual) => { assert.ok('x5t#S256' in Object(actual)); assert.equal(actual['x5t#S256'], expectedS256); })(AccessToken);
      ((actual) => { assert.ok('x5t#S256' in Object(actual)); assert.equal(actual['x5t#S256'], expectedS256); })(RefreshToken);
    });
  });

  describe('urn:openid:params:grant-type:ciba', () => {
    const fixture5 = Object.create(fixture);

    beforeEach(async () => {
      await fixture5.agent.post('/backchannel')
        .auth('client', 'secret')
        .send({
          scope: 'openid offline_access',
          login_hint: 'accountId',
        })
        .type('form')
        .expect(200)
        .expect(({ body: { auth_req_id: reqId } }) => {
          fixture5.reqId = reqId;
        });
    }, { timeout: 3000 });

    it('binds the access token to the certificate', { timeout: 3000 }, async () => {
      const spy = sinon.spy();
      fixture5.provider.once('grant.success', spy);

      await fixture5.agent.post('/token')
        .auth('client', 'secret')
        .send({
          grant_type: 'urn:openid:params:grant-type:ciba',
          auth_req_id: fixture5.reqId,
        })
        .type('form')
        .set('x-ssl-client-cert', crt.raw.toString('base64'))
        .expect(200);

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
      const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
      ((actual) => { assert.ok('x5t#S256' in Object(actual)); assert.equal(actual['x5t#S256'], expectedS256); })(AccessToken);
      assert.ok(!('x5t#S256' in Object(RefreshToken)));
    });

    it('verifies the request made with mutual-TLS', { timeout: 3000 }, async () => {
      const spy = sinon.spy();
      fixture5.provider.once('grant.error', spy);

      await fixture5.agent.post('/token')
        .auth('client', 'secret')
        .send({
          grant_type: 'urn:openid:params:grant-type:ciba',
          auth_req_id: fixture5.reqId,
        })
        .type('form')
        .expect(400)
        .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
      ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'mutual TLS client certificate not provided'); })(spy.args[0][1]);
    });

    it('binds the refresh token to the certificate for public clients', { timeout: 3000 }, async () => {
      const spy = sinon.spy();
      fixture5.provider.once('grant.success', spy);

      // changes the code to client-none
      fixture5.TestAdapter.for('BackchannelAuthenticationRequest').syncUpdate(fixture5.getTokenJti(fixture5.reqId), {
        clientId: 'client-none',
      });
      const { grantId } = fixture5.TestAdapter.for('BackchannelAuthenticationRequest').syncFind(fixture5.getTokenJti(fixture5.reqId));
      fixture5.TestAdapter.for('Grant').syncUpdate(grantId, {
        clientId: 'client-none',
      });

      await fixture5.agent.post('/token')
        .send({
          client_id: 'client-none',
          grant_type: 'urn:openid:params:grant-type:ciba',
          auth_req_id: fixture5.reqId,
        })
        .type('form')
        .set('x-ssl-client-cert', crt.raw.toString('base64'))
        .expect(200);

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
      const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
      ((actual) => { assert.ok('x5t#S256' in Object(actual)); assert.equal(actual['x5t#S256'], expectedS256); })(AccessToken);
      ((actual) => { assert.ok('x5t#S256' in Object(actual)); assert.equal(actual['x5t#S256'], expectedS256); })(RefreshToken);
    });
  });

  describe('authorization flow', () => {
    const fixture6 = Object.create(fixture);

    before(() => fixture6.login({ scope: 'openid offline_access' }), { timeout: 3000 });
    skipConsent(fixture6);

    beforeEach(async () => {
      // biome-ignore lint/suspicious/noAssignInExpressions: test pattern
      const auth = fixture6.auth = new fixture6.AuthorizationRequest({
        response_type: 'code',
        scope: 'openid offline_access',
        prompt: 'consent',
      });

      await fixture6.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validateClientLocation)
        .expect(({ headers: { location } }) => {
          const { query: { code } } = url.parse(location, true);
          fixture6.code = code;
        });
    }, { timeout: 3000 });

    describe('authorization_code', () => {
      const fixture7 = Object.create(fixture6);

      it('binds the access token to the certificate', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture7.provider.once('grant.success', spy);

        await fixture7.agent.post('/token')
          .auth('client', 'secret')
          .send({
            grant_type: 'authorization_code',
            code_verifier: fixture7.auth.code_verifier,
            code: fixture7.code,
            redirect_uri: 'https://client.example.com/cb',
          })
          .type('form')
          .set('x-ssl-client-cert', crt.raw.toString('base64'))
          .expect(200);

        ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
        const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
        ((actual) => { assert.ok('x5t#S256' in Object(actual)); assert.equal(actual['x5t#S256'], expectedS256); })(AccessToken);
        assert.ok(!('x5t#S256' in Object(RefreshToken)));
      });

      it('verifies the request made with mutual-TLS', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture7.provider.once('grant.error', spy);

        await fixture7.agent.post('/token')
          .auth('client', 'secret')
          .send({
            grant_type: 'authorization_code',
            code_verifier: fixture7.auth.code_verifier,
            code: fixture7.code,
            redirect_uri: 'https://client.example.com/cb',
          })
          .type('form')
          .expect(400)
          .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

        ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
        ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'mutual TLS client certificate not provided'); })(spy.args[0][1]);
      });
    });

    describe('refresh_token', () => {
      const fixture8 = Object.create(fixture6);

      beforeEach(async () => {
        await fixture8.agent.post('/token')
          .auth('client', 'secret')
          .send({
            grant_type: 'authorization_code',
            code_verifier: fixture8.auth.code_verifier,
            code: fixture8.code,
            redirect_uri: 'https://client.example.com/cb',
          })
          .type('form')
          .set('x-ssl-client-cert', crt.raw.toString('base64'))
          .expect(({ body }) => {
            fixture8.rt = body.refresh_token;
          });
      }, { timeout: 3000 });

      it('binds the access token to the certificate', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture8.provider.once('grant.success', spy);

        await fixture8.agent.post('/token')
          .auth('client', 'secret')
          .send({
            grant_type: 'refresh_token',
            refresh_token: fixture8.rt,
          })
          .type('form')
          .set('x-ssl-client-cert', crt.raw.toString('base64'))
          .expect(200);

        ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
        const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
        ((actual) => { assert.ok('x5t#S256' in Object(actual)); assert.equal(actual['x5t#S256'], expectedS256); })(AccessToken);
        assert.equal(RefreshToken['x5t#S256'], undefined);
      });

      it('verifies the request made with mutual-TLS', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture8.provider.once('grant.error', spy);

        await fixture8.agent.post('/token')
          .auth('client', 'secret')
          .send({
            grant_type: 'refresh_token',
            refresh_token: fixture8.rt,
          })
          .type('form')
          .expect(400)
          .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

        ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
        ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'mutual TLS client certificate not provided'); })(spy.args[0][1]);
      });
    });
  });

  describe('authorization flow (public client)', () => {
    const fixture9 = Object.create(fixture);

    before(() => fixture9.login({ scope: 'openid offline_access' }), { timeout: 3000 });
    skipConsent(fixture9);

    beforeEach(async () => {
      // biome-ignore lint/suspicious/noAssignInExpressions: test pattern
      const auth = fixture9.auth = new fixture9.AuthorizationRequest({
        client_id: 'client-none',
        response_type: 'code',
        scope: 'openid offline_access',
        prompt: 'consent',
      });

      await fixture9.wrap({ route: '/auth', verb: 'get', auth })
        .expect(303)
        .expect(auth.validateClientLocation)
        .expect(({ headers: { location } }) => {
          const { query: { code } } = url.parse(location, true);
          fixture9.code = code;
        });
    }, { timeout: 3000 });

    describe('authorization_code', () => {
      const fixture10 = Object.create(fixture9);

      it('binds the access token to the certificate', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture10.provider.once('grant.success', spy);

        await fixture10.agent.post('/token')
          .send({
            client_id: 'client-none',
            grant_type: 'authorization_code',
            code_verifier: fixture10.auth.code_verifier,
            code: fixture10.code,
            redirect_uri: 'https://client.example.com/cb',
          })
          .type('form')
          .set('x-ssl-client-cert', crt.raw.toString('base64'))
          .expect(200);

        ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
        const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
        ((actual) => { assert.ok('x5t#S256' in Object(actual)); assert.equal(actual['x5t#S256'], expectedS256); })(AccessToken);
        ((actual) => { assert.ok('x5t#S256' in Object(actual)); assert.equal(actual['x5t#S256'], expectedS256); })(RefreshToken);
      });

      it('verifies the request made with mutual-TLS', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture10.provider.once('grant.error', spy);

        await fixture10.agent.post('/token')
          .send({
            client_id: 'client-none',
            grant_type: 'authorization_code',
            code_verifier: fixture10.auth.code_verifier,
            code: fixture10.code,
            redirect_uri: 'https://client.example.com/cb',
          })
          .type('form')
          .expect(400)
          .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

        ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
        ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'mutual TLS client certificate not provided'); })(spy.args[0][1]);
      });
    });

    describe('refresh_token', () => {
      const fixture11 = Object.create(fixture9);

      beforeEach(async () => {
        await fixture11.agent.post('/token')
          .send({
            client_id: 'client-none',
            grant_type: 'authorization_code',
            code_verifier: fixture11.auth.code_verifier,
            code: fixture11.code,
            redirect_uri: 'https://client.example.com/cb',
          })
          .type('form')
          .set('x-ssl-client-cert', crt.raw.toString('base64'))
          .expect(({ body }) => {
            fixture11.rt = body.refresh_token;
          });
      }, { timeout: 3000 });

      it('binds the access token to the certificate', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture11.provider.once('grant.success', spy);

        await fixture11.agent.post('/token')
          .send({
            client_id: 'client-none',
            grant_type: 'refresh_token',
            refresh_token: fixture11.rt,
          })
          .type('form')
          .set('x-ssl-client-cert', crt.raw.toString('base64'))
          .expect(200);

        ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
        const { oidc: { entities: { AccessToken, RefreshToken } } } = spy.args[0][0];
        ((actual) => { assert.ok('x5t#S256' in Object(actual)); assert.equal(actual['x5t#S256'], expectedS256); })(AccessToken);
        ((actual) => { assert.ok('x5t#S256' in Object(actual)); assert.equal(actual['x5t#S256'], expectedS256); })(RefreshToken);
      });

      it('verifies the request made with mutual-TLS', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture11.provider.once('grant.error', spy);

        await fixture11.agent.post('/token')
          .send({
            client_id: 'client-none',
            grant_type: 'refresh_token',
            refresh_token: fixture11.rt,
          })
          .type('form')
          .expect(400)
          .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

        ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
        ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'mutual TLS client certificate not provided'); })(spy.args[0][1]);
      });

      it('verifies the request made with mutual-TLS using the same cert', { timeout: 3000 }, async () => {
        const spy = sinon.spy();
        fixture11.provider.once('grant.error', spy);

        await fixture11.agent.post('/token')
          .send({
            client_id: 'client-none',
            grant_type: 'refresh_token',
            refresh_token: fixture11.rt,
          })
          .set('x-ssl-client-cert', new X509Certificate(readFileSync('./test/jwks/rsa.crt', { encoding: 'ascii' })).raw.toString('base64'))
          .type('form')
          .expect(400)
          .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

        ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
        ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'failed x5t#S256 verification'); })(spy.args[0][1]);
      });
    });
  });

  describe('client_credentials', () => {
    const fixture12 = Object.create(fixture);

    it('binds the access token to the certificate', { timeout: 3000 }, async () => {
      const spy = sinon.spy();
      fixture12.provider.once('grant.success', spy);

      await fixture12.agent.post('/token')
        .auth('client', 'secret')
        .send({ grant_type: 'client_credentials' })
        .set('x-ssl-client-cert', crt.raw.toString('base64'))
        .type('form')
        .expect(200);

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
      const { oidc: { entities: { ClientCredentials } } } = spy.args[0][0];
      ((actual) => { assert.ok('x5t#S256' in Object(actual)); assert.equal(actual['x5t#S256'], expectedS256); })(ClientCredentials);
    });

    it('verifies the request was made with mutual-TLS', { timeout: 3000 }, async () => {
      const spy = sinon.spy();
      fixture12.provider.once('grant.error', spy);

      await fixture12.agent.post('/token')
        .auth('client', 'secret')
        .send({ grant_type: 'client_credentials' })
        .type('form')
        .expect(400)
        .expect({ error: 'invalid_grant', error_description: 'grant request is invalid' });

      ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(spy);
      ((actual) => { assert.ok('error_detail' in Object(actual)); assert.equal(actual.error_detail, 'mutual TLS client certificate not provided'); })(spy.args[0][1]);
    });
  });
});
