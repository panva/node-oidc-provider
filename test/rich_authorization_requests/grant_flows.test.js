import { describe, before, beforeEach, it } from 'node:test';
import assert from 'node:assert/strict';
import sinon from 'sinon';

import bootstrap from '../test_helper.js';
import { rarState, resetRarState } from './rich_authorization_requests.config.js';

const API = 'https://api.example.com';
const JWT_API = 'https://jwt.example.com';
const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';
const CIBA_GRANT = 'urn:openid:params:grant-type:ciba';

const broad = [{
  type: 'payment',
  actions: ['read', 'initiate'],
  currency: 'EUR',
  amount: 10,
}];

const narrow = [{
  type: 'payment',
  actions: ['read'],
  currency: 'EUR',
  amount: 10,
}];

describe('Rich Authorization Requests grant flows', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture, { config: 'rich_authorization_requests' }), { timeout: 3000 });

  beforeEach(async () => {
    resetRarState();
    await fixture.login({
      accountId: 'account',
      scope: 'openid api:read',
      resources: {
        [API]: 'api:read',
        [JWT_API]: 'api:read',
      },
    });
  }, { timeout: 3000 });

  async function grantWithRar() {
    const grant = new this.provider.Grant({
      accountId: 'account',
      clientId: 'client',
    });
    grant.addResourceScope(API, 'api:read');
    for (const detail of broad) grant.addRar(detail);
    await grant.save();
    return grant;
  }

  it('persists consented details, narrows authorization-code tokens, and preserves the broad refresh grant', { timeout: 3000 }, async () => {
    const auth = new fixture.AuthorizationRequest({
      response_type: 'code',
      scope: 'api:read',
      resource: JWT_API,
      authorization_details: JSON.stringify(broad),
    });

    let location;
    await fixture.wrap({ route: '/auth', verb: 'get', auth })
      .expect(303)
      .expect((response) => {
        ({ location } = response.headers);
        assert.match(new URL(location, fixture.provider.issuer).pathname, new RegExp(`^${fixture.suitePath('/interaction/')}`));
      });

    await fixture.agent.post(location)
      .send({ prompt: 'consent' })
      .type('form')
      .expect(303)
      .expect((response) => {
        ({ location } = response.headers);
      });

    await fixture.agent.get(new URL(location, fixture.provider.issuer).pathname)
      .expect(303)
      .expect(auth.validatePresence(['code', 'state']));

    const authorizationCode = await fixture.provider.AuthorizationCode.find(auth.res.code);
    assert.deepEqual(authorizationCode.rar, broad);
    assert.equal(rarState.grantSourceCalls.length, 1);
    ((actual) => { assert.ok('kind' in Object(actual)); assert.equal(actual.kind, 'AuthorizationCode'); })(rarState.grantSourceCalls[0]);
    assert.deepEqual(rarState.grantSourceCalls[0].rar, broad);

    const refreshTokenSaved = sinon.spy();
    fixture.provider.once('refresh_token.saved', refreshTokenSaved);

    const response = await fixture.agent.post('/token')
      .auth('client', 'secret')
      .type('form')
      .send({
        grant_type: 'authorization_code',
        code: auth.res.code,
        code_verifier: auth.code_verifier,
        redirect_uri: auth.redirect_uri,
        resource: JWT_API,
        authorization_details: JSON.stringify(narrow),
      })
      .expect(200);

    assert.equal(rarState.accessTokenCalls.length, 1);
    ((actual) => { assert.ok("grantType" in Object(actual)); assert.equal(actual.grantType, 'authorization_code'); assert.ok("resource" in Object(actual)); assert.equal(actual.resource, JWT_API); })(rarState.accessTokenCalls[0]);
    ((actual) => { assert.ok('kind' in Object(actual)); assert.equal(actual.kind, 'AuthorizationCode'); })(rarState.accessTokenCalls[0].source);

    const accessToken = rarState.accessTokenCalls[0].token;
    const refreshToken = refreshTokenSaved.firstCall.args[0];
    assert.deepEqual(accessToken.rar, narrow);
    assert.deepEqual(refreshToken.rar, broad);
    assert.deepEqual(response.body.authorization_details, accessToken.rar);

    const payload = JSON.parse(Buffer.from(
      response.body.access_token.split('.')[1],
      'base64url',
    ));
    assert.deepEqual(payload.authorization_details, narrow);

    resetRarState();
    const refreshResponse = await fixture.agent.post('/token')
      .auth('client', 'secret')
      .type('form')
      .send({
        grant_type: 'refresh_token',
        refresh_token: response.body.refresh_token,
        resource: JWT_API,
        authorization_details: JSON.stringify(narrow),
      })
      .expect(200);

    assert.equal(rarState.accessTokenCalls.length, 1);
    assert.equal(rarState.accessTokenCalls[0].grantType, 'refresh_token');
    ((actual) => { assert.ok('kind' in Object(actual)); assert.equal(actual.kind, 'RefreshToken'); })(rarState.accessTokenCalls[0].source);
    assert.deepEqual(rarState.accessTokenCalls[0].source.rar, broad);
    assert.deepEqual(refreshResponse.body.authorization_details, narrow);
  });

  it('supports device-code RAR and device-origin refresh narrowing', { timeout: 3000 }, async () => {
    let code;
    let userCode;
    await fixture.agent.post('/device/auth')
      .auth('client', 'secret')
      .send({
        client_id: 'client',
        resource: API,
        scope: 'api:read',
        authorization_details: JSON.stringify(broad),
      })
      .type('form')
      .expect(200)
      .expect(({ body }) => {
        code = body.device_code;
        userCode = body.user_code;
      });

    fixture.getSession().state = { secret: 'foo' };

    let location;
    await fixture.agent.post('/device')
      .send({
        user_code: userCode,
        xsrf: 'foo',
        confirm: true,
      })
      .type('form')
      .expect(303)
      .expect((response) => {
        ({ location } = response.headers);
      });

    await fixture.agent.post(location)
      .send({ prompt: 'consent' })
      .type('form')
      .expect(303)
      .expect((response) => {
        ({ location } = response.headers);
      });

    await fixture.agent.get(new URL(location, fixture.provider.issuer).pathname)
      .expect(200);

    const deviceCode = await fixture.provider.DeviceCode.find(code);
    assert.deepEqual(deviceCode.rar, broad);
    assert.equal(rarState.grantSourceCalls.length, 1);
    ((actual) => { assert.ok('kind' in Object(actual)); assert.equal(actual.kind, 'DeviceCode'); })(rarState.grantSourceCalls[0]);
    assert.deepEqual(rarState.grantSourceCalls[0].rar, broad);

    resetRarState();

    const accessTokenSaved = sinon.spy();
    const refreshTokenSaved = sinon.spy();
    fixture.provider.once('access_token.saved', accessTokenSaved);
    fixture.provider.once('refresh_token.saved', refreshTokenSaved);

    const response = await fixture.agent.post('/token')
      .auth('client', 'secret')
      .type('form')
      .send({
        client_id: 'client',
        device_code: code,
        grant_type: DEVICE_GRANT,
        resource: API,
        authorization_details: JSON.stringify(narrow),
      })
      .expect(200);

    assert.equal(rarState.accessTokenCalls.length, 1);
    assert.equal(rarState.accessTokenCalls[0].grantType, DEVICE_GRANT);
    ((actual) => { assert.ok('kind' in Object(actual)); assert.equal(actual.kind, 'DeviceCode'); })(rarState.accessTokenCalls[0].source);
    assert.deepEqual(accessTokenSaved.firstCall.args[0].rar, narrow);
    assert.deepEqual(refreshTokenSaved.firstCall.args[0].rar, broad);
    assert.deepEqual(response.body.authorization_details, narrow);

    resetRarState();
    const refreshResponse = await fixture.agent.post('/token')
      .auth('client', 'secret')
      .type('form')
      .send({
        grant_type: 'refresh_token',
        refresh_token: response.body.refresh_token,
        resource: API,
        authorization_details: JSON.stringify(narrow),
      })
      .expect(200);

    assert.equal(rarState.accessTokenCalls.length, 1);
    assert.equal(rarState.accessTokenCalls[0].grantType, 'refresh_token');
    assert.deepEqual(rarState.accessTokenCalls[0].source.rar, broad);
    assert.deepEqual(refreshResponse.body.authorization_details, narrow);
  });

  it('clears inherited RAR when access-token policy returns undefined', { timeout: 3000 }, async () => {
    const grant = new fixture.provider.Grant({
      accountId: 'account',
      clientId: 'client',
    });
    grant.addOIDCScope('api:read');
    for (const detail of broad) grant.addRar(detail);
    await grant.save();
    const deviceCode = new fixture.provider.DeviceCode({
      accountId: 'account',
      clientId: 'client',
      grantId: grant.jti,
      rar: broad,
      scope: 'api:read',
    });
    const code = await deviceCode.save();
    const accessTokenSaved = sinon.spy();
    fixture.provider.once('access_token.saved', accessTokenSaved);
    rarState.clearAccessTokenResult = true;

    const response = await fixture.agent.post('/token')
      .auth('client', 'secret')
      .type('form')
      .send({
        client_id: 'client',
        device_code: code,
        grant_type: DEVICE_GRANT,
      })
      .expect(200);

    assert.equal(rarState.accessTokenCalls.length, 1);
    assert.equal(rarState.accessTokenCalls[0].resource, undefined);
    assert.deepEqual(rarState.accessTokenCalls[0].source.rar, broad);
    assert.equal(accessTokenSaved.firstCall.args[0].rar, undefined);
    assert.ok(!('authorization_details' in Object(response.body)));
  });

  it('supports CIBA RAR and passes the exact grant type', { timeout: 3000 }, async () => {
    const grant = await grantWithRar.call(fixture);
    const request = new fixture.provider.BackchannelAuthenticationRequest({
      accountId: 'account',
      clientId: 'client',
      resource: API,
      scope: 'api:read',
    });
    await fixture.provider.backchannelResult(request, grant, { rar: broad });

    const response = await fixture.agent.post('/token')
      .auth('client', 'secret')
      .type('form')
      .send({
        auth_req_id: request.jti,
        grant_type: CIBA_GRANT,
        resource: API,
        authorization_details: JSON.stringify(narrow),
      })
      .expect(200);

    assert.equal(rarState.accessTokenCalls.length, 1);
    assert.equal(rarState.accessTokenCalls[0].grantType, CIBA_GRANT);
    ((actual) => { assert.ok('kind' in Object(actual)); assert.equal(actual.kind, 'BackchannelAuthenticationRequest'); })(rarState.accessTokenCalls[0].source);
    assert.deepEqual(response.body.authorization_details, narrow);
  });

  it('passes each introspectable RAR token kind to the introspection policy', { timeout: 3000 }, async () => {
    const client = await fixture.provider.Client.find('client');
    const common = {
      client,
      rar: narrow,
      scope: 'api:read',
    };
    const tokens = [
      new fixture.provider.AccessToken({
        ...common,
        accountId: 'account',
        aud: API,
        grantId: fixture.getGrantId(),
      }),
      new fixture.provider.ClientCredentials({
        ...common,
        aud: API,
      }),
      new fixture.provider.RefreshToken({
        ...common,
        accountId: 'account',
        grantId: fixture.getGrantId(),
      }),
    ];

    for (const token of tokens) {
      const value = await token.save();
      resetRarState();

      await fixture.agent.post('/token/introspection')
        .auth('client', 'secret')
        .type('form')
        .send({ token: value })
        .expect(200)
        .expect((introspection) => {
          ((actual) => { assert.ok('active' in Object(actual)); assert.equal(actual.active, true); })(introspection.body);
          assert.deepEqual(introspection.body.authorization_details, narrow);
        });

      assert.equal(rarState.introspectionCalls.length, 1);
      const [call] = rarState.introspectionCalls;
      ((actual) => { assert.ok('clientId' in Object(actual)); assert.equal(actual.clientId, 'client'); })(call.client);
      assert.ok(call.token instanceof token.constructor);
      ((actual) => { assert.ok('kind' in Object(actual)); assert.equal(actual.kind, token.kind); })(call.token);
      assert.deepEqual(call.token.rar, narrow);
    }
  });

  it('allows the introspection policy to filter stored RAR by token audience', { timeout: 3000 }, async () => {
    const authorizationDetails = [{
      ...narrow[0],
      locations: [API],
    }, {
      ...broad[0],
      locations: [JWT_API],
    }];
    const response = await fixture.agent.post('/token')
      .auth('client', 'secret')
      .type('form')
      .send({
        grant_type: 'client_credentials',
        resource: API,
        scope: 'api:read',
        authorization_details: JSON.stringify(authorizationDetails),
      })
      .expect(200);

    rarState.filterIntrospectionByAudience = true;

    await fixture.agent.post('/token/introspection')
      .auth('client', 'secret')
      .type('form')
      .send({ token: response.body.access_token })
      .expect(200)
      .expect((introspection) => {
        ((actual) => { assert.ok('active' in Object(actual)); assert.equal(actual.active, true); })(introspection.body);
        assert.deepEqual(introspection.body.authorization_details, [authorizationDetails[0]]);
      });

    assert.equal(rarState.introspectionCalls.length, 1);
    const [call] = rarState.introspectionCalls;
    ((actual) => { assert.ok('clientId' in Object(actual)); assert.equal(actual.clientId, 'client'); })(call.client);
    assert.ok(call.token instanceof fixture.provider.ClientCredentials);
    ((actual) => { assert.ok('aud' in Object(actual)); assert.equal(actual.aud, API); })(call.token);
    ((actual) => { assert.ok('kind' in Object(actual)); assert.equal(actual.kind, 'ClientCredentials'); })(call.token);
    assert.deepEqual(call.token.rar, authorizationDetails);
  });

  it('normalizes an empty introspection policy result to an omitted member', { timeout: 3000 }, async () => {
    const token = new fixture.provider.ClientCredentials({
      aud: API,
      client: await fixture.provider.Client.find('client'),
      rar: narrow,
      scope: 'api:read',
    });
    const value = await token.save();
    rarState.emptyIntrospectionResult = true;

    await fixture.agent.post('/token/introspection')
      .auth('client', 'secret')
      .type('form')
      .send({ token: value })
      .expect(200)
      .expect((introspection) => {
        ((actual) => { assert.ok('active' in Object(actual)); assert.equal(actual.active, true); })(introspection.body);
        assert.ok(!('authorization_details' in Object(introspection.body)));
      });

    assert.equal(rarState.introspectionCalls.length, 1);
    assert.deepEqual(rarState.introspectionCalls[0].token.rar, narrow);
  });

  it('treats malformed introspection policy output as a server configuration error', { timeout: 3000 }, async () => {
    const token = new fixture.provider.ClientCredentials({
      aud: API,
      client: await fixture.provider.Client.find('client'),
      rar: narrow,
      scope: 'api:read',
    });
    const value = await token.save();
    const serverError = sinon.spy();
    fixture.provider.once('server_error', serverError);
    rarState.invalidIntrospectionResult = true;

    await fixture.agent.post('/token/introspection')
      .auth('client', 'secret')
      .type('form')
      .send({ token: value })
      .expect(500)
      .expect({
        error: 'server_error',
        error_description: 'oops! something went wrong',
      });

    assert.equal(rarState.introspectionCalls.length, 1);
    ((actual) => { assert.ok('calledOnce' in Object(actual)); assert.equal(actual.calledOnce, true); })(serverError);
    assert.ok(serverError.firstCall.args[1] instanceof TypeError);
    assert.equal(serverError.firstCall.args[1].message, 'authorization details policy result members should be a JSON object');
  });
});
