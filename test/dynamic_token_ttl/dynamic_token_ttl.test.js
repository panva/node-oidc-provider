import { describe, before, afterEach, it } from 'node:test';
import assert from 'node:assert/strict';
import * as url from 'node:url';

import sinon from 'sinon';
import cloneDeep from 'lodash/cloneDeep.js';

import bootstrap, { skipConsent } from '../test_helper.js';
import * as JWT from '../../lib/helpers/jwt.js';

describe('dynamic ttl', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });
  skipConsent(fixture);
  before(() => {
    fixture.prev = cloneDeep(i(fixture.provider).configuration.ttl);
  }, { timeout: 3000 });
  afterEach(() => {
    i(fixture.provider).configuration.ttl = fixture.prev;
  }, { timeout: 3000 });
  before(() => fixture.login({ scope: 'openid offline_access' }), { timeout: 3000 });

  it('client credentials', { timeout: 3000 }, async () => {
    const ClientCredentials = sinon.fake.returns(123);
    i(fixture.provider).configuration.ttl.ClientCredentials = ClientCredentials;

    await fixture.agent.post('/token')
      .send({
        client_id: 'client',
        grant_type: 'client_credentials',
      })
      .type('form')
      .expect(200)
      .expect(({ body: { expires_in } }) => {
        assert.deepEqual(expires_in, 123);
      });

    ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(ClientCredentials);
    ((actual) => { assert.ok(actual instanceof fixture.provider.ClientCredentials); })(ClientCredentials.args[0][1]);
    ((actual) => { assert.ok(actual instanceof fixture.provider.Client); })(ClientCredentials.args[0][2]);
  });

  it('device flow init', { timeout: 3000 }, async () => {
    const DeviceCode = sinon.fake.returns(123);
    i(fixture.provider).configuration.ttl.DeviceCode = DeviceCode;

    let device_code;
    await fixture.agent.post('/device/auth')
      .send({
        client_id: 'client',
        scope: 'openid offline_access',
        prompt: 'consent',
      })
      .type('form')
      .expect(200)
      .expect(({ body: { expires_in, device_code: dc } }) => {
        assert.deepEqual(expires_in, 123);
        device_code = dc;
      });

    ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(DeviceCode);
    ((actual) => { assert.ok(actual instanceof fixture.provider.DeviceCode); })(DeviceCode.args[0][1]);
    ((actual) => { assert.ok(actual instanceof fixture.provider.Client); })(DeviceCode.args[0][2]);

    fixture.TestAdapter.for('DeviceCode').syncUpdate(fixture.getTokenJti(device_code), {
      scope: 'openid offline_access',
      accountId: fixture.loggedInAccountId,
      grantId: fixture.getGrantId('client'),
    });

    const IdToken = sinon.fake.returns(123);
    const AccessToken = sinon.fake.returns(1234);
    const RefreshToken = sinon.fake.returns(12345);
    i(fixture.provider).configuration.ttl.IdToken = IdToken;
    i(fixture.provider).configuration.ttl.AccessToken = AccessToken;
    i(fixture.provider).configuration.ttl.RefreshToken = RefreshToken;

    await fixture.agent.post('/token')
      .send({
        client_id: 'client',
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        device_code,
      })
      .type('form')
      .expect(200);

    ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(IdToken);
    ((actual) => { assert.ok(actual instanceof fixture.provider.IdToken); })(IdToken.args[0][1]);
    ((actual) => { assert.ok(actual instanceof fixture.provider.Client); })(IdToken.args[0][2]);

    ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(AccessToken);
    ((actual) => { assert.ok(actual instanceof fixture.provider.AccessToken); })(AccessToken.args[0][1]);
    ((actual) => { assert.ok(actual instanceof fixture.provider.Client); })(AccessToken.args[0][2]);

    ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(RefreshToken);
    ((actual) => { assert.ok(actual instanceof fixture.provider.RefreshToken); })(RefreshToken.args[0][1]);
    ((actual) => { assert.ok(actual instanceof fixture.provider.Client); })(RefreshToken.args[0][2]);
  });

  it('authorization flow returned tokens', { timeout: 3000 }, async () => {
    const IdToken = sinon.fake.returns(123);
    const AccessToken = sinon.fake.returns(1234);
    const AuthorizationCode = sinon.fake.returns(12);
    i(fixture.provider).configuration.ttl.IdToken = IdToken;
    i(fixture.provider).configuration.ttl.AccessToken = AccessToken;
    i(fixture.provider).configuration.ttl.AuthorizationCode = AuthorizationCode;

    const auth = new fixture.AuthorizationRequest({
      response_type: 'code id_token token',
      scope: 'openid',
    });

    await fixture.wrap({ route: '/auth', verb: 'get', auth })
      .expect(303)
      .expect(auth.validateFragment)
      .expect(({ headers: { location } }) => {
        const { query: { expires_in, id_token } } = url.parse(location, true);
        assert.deepEqual(expires_in, '1234');
        const { payload: { iat, exp } } = JWT.decode(id_token);
        assert.deepEqual(exp - iat, 123);
      });

    ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(IdToken);
    ((actual) => { assert.ok(actual instanceof fixture.provider.IdToken); })(IdToken.args[0][1]);
    ((actual) => { assert.ok(actual instanceof fixture.provider.Client); })(IdToken.args[0][2]);

    ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(AccessToken);
    ((actual) => { assert.ok(actual instanceof fixture.provider.AccessToken); })(AccessToken.args[0][1]);
    ((actual) => { assert.ok(actual instanceof fixture.provider.Client); })(AccessToken.args[0][2]);

    ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(AuthorizationCode);
    ((actual) => { assert.ok(actual instanceof fixture.provider.AuthorizationCode); })(AuthorizationCode.args[0][1]);
    ((actual) => { assert.ok(actual instanceof fixture.provider.Client); })(AuthorizationCode.args[0][2]);
  });

  it('authorization code', { timeout: 3000 }, async () => {
    const IdToken = sinon.fake.returns(123);
    const AccessToken = sinon.fake.returns(1234);
    const RefreshToken = sinon.fake.returns(12345);
    i(fixture.provider).configuration.ttl.IdToken = IdToken;
    i(fixture.provider).configuration.ttl.AccessToken = AccessToken;
    i(fixture.provider).configuration.ttl.RefreshToken = RefreshToken;

    const auth = new fixture.AuthorizationRequest({
      response_type: 'code',
      scope: 'openid offline_access',
      prompt: 'consent',
    });

    let code;

    await fixture.wrap({ route: '/auth', verb: 'get', auth })
      .expect(303)
      .expect(({ headers: { location } }) => {
        ({ query: { code } } = url.parse(location, true));
      });

    await fixture.agent.post('/token')
      .send({
        client_id: 'client',
        grant_type: 'authorization_code',
        code_verifier: auth.code_verifier,
        code,
        redirect_uri: 'https://rp.example.com/cb',
      })
      .type('form')
      .expect(200);

    ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(IdToken);
    ((actual) => { assert.ok(actual instanceof fixture.provider.IdToken); })(IdToken.args[0][1]);
    ((actual) => { assert.ok(actual instanceof fixture.provider.Client); })(IdToken.args[0][2]);

    ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(AccessToken);
    ((actual) => { assert.ok(actual instanceof fixture.provider.AccessToken); })(AccessToken.args[0][1]);
    ((actual) => { assert.ok(actual instanceof fixture.provider.Client); })(AccessToken.args[0][2]);

    ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(RefreshToken);
    ((actual) => { assert.ok(actual instanceof fixture.provider.RefreshToken); })(RefreshToken.args[0][1]);
    ((actual) => { assert.ok(actual instanceof fixture.provider.Client); })(RefreshToken.args[0][2]);
  });

  it('refreshed tokens', { timeout: 3000 }, async () => {
    const auth = new fixture.AuthorizationRequest({
      response_type: 'code',
      scope: 'openid offline_access',
      prompt: 'consent',
    });

    let code;

    await fixture.wrap({ route: '/auth', verb: 'get', auth })
      .expect(303)
      .expect(({ headers: { location } }) => {
        ({ query: { code } } = url.parse(location, true));
      });

    let refresh_token;

    await fixture.agent.post('/token')
      .send({
        client_id: 'client',
        grant_type: 'authorization_code',
        code_verifier: auth.code_verifier,
        code,
        redirect_uri: 'https://rp.example.com/cb',
      })
      .type('form')
      .expect(200)
      .expect(({ body: { refresh_token: rt } }) => {
        refresh_token = rt;
      });

    const IdToken = sinon.fake.returns(123);
    const AccessToken = sinon.fake.returns(1234);
    const RefreshToken = sinon.fake.returns(12345);
    i(fixture.provider).configuration.ttl.IdToken = IdToken;
    i(fixture.provider).configuration.ttl.AccessToken = AccessToken;
    i(fixture.provider).configuration.ttl.RefreshToken = RefreshToken;

    await fixture.agent.post('/token')
      .send({
        client_id: 'client',
        grant_type: 'refresh_token',
        refresh_token,
        redirect_uri: 'https://rp.example.com/cb',
      })
      .type('form')
      .expect(200);

    ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(IdToken);
    ((actual) => { assert.ok(actual instanceof fixture.provider.IdToken); })(IdToken.args[0][1]);
    ((actual) => { assert.ok(actual instanceof fixture.provider.Client); })(IdToken.args[0][2]);

    ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(AccessToken);
    ((actual) => { assert.ok(actual instanceof fixture.provider.AccessToken); })(AccessToken.args[0][1]);
    ((actual) => { assert.ok(actual instanceof fixture.provider.Client); })(AccessToken.args[0][2]);

    ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(RefreshToken);
    ((actual) => { assert.ok(actual instanceof fixture.provider.RefreshToken); })(RefreshToken.args[0][1]);
    ((actual) => { assert.ok(actual instanceof fixture.provider.Client); })(RefreshToken.args[0][2]);
  });
});
