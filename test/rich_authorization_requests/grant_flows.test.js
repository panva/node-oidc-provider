import { expect } from 'chai';
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
  before(bootstrap(import.meta.url, { config: 'rich_authorization_requests' }));

  beforeEach(async function () {
    resetRarState();
    await this.login({
      accountId: 'account',
      scope: 'openid api:read',
      resources: {
        [API]: 'api:read',
        [JWT_API]: 'api:read',
      },
    });
  });

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

  it('persists consented details, narrows authorization-code tokens, and preserves the broad refresh grant', async function () {
    const auth = new this.AuthorizationRequest({
      response_type: 'code',
      scope: 'api:read',
      resource: JWT_API,
      authorization_details: JSON.stringify(broad),
    });

    let location;
    await this.wrap({ route: '/auth', verb: 'get', auth })
      .expect(303)
      .expect((response) => {
        ({ location } = response.headers);
        expect(new URL(location, this.provider.issuer).pathname).to.match(/^\/interaction\//);
      });

    await this.agent.post(location)
      .send({ prompt: 'consent' })
      .type('form')
      .expect(303)
      .expect((response) => {
        ({ location } = response.headers);
      });

    await this.agent.get(new URL(location, this.provider.issuer).pathname)
      .expect(303)
      .expect(auth.validatePresence(['code', 'state']));

    const authorizationCode = await this.provider.AuthorizationCode.find(auth.res.code);
    expect(authorizationCode.rar).to.deep.equal(broad);
    expect(rarState.grantSourceCalls).to.have.lengthOf(1);
    expect(rarState.grantSourceCalls[0]).to.have.property('kind', 'AuthorizationCode');
    expect(rarState.grantSourceCalls[0].rar).to.deep.equal(broad);

    const refreshTokenSaved = sinon.spy();
    this.provider.once('refresh_token.saved', refreshTokenSaved);

    const response = await this.agent.post('/token')
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

    expect(rarState.accessTokenCalls).to.have.lengthOf(1);
    expect(rarState.accessTokenCalls[0]).to.include({
      grantType: 'authorization_code',
      resource: JWT_API,
    });
    expect(rarState.accessTokenCalls[0].source).to.have.property('kind', 'AuthorizationCode');

    const accessToken = rarState.accessTokenCalls[0].token;
    const refreshToken = refreshTokenSaved.firstCall.args[0];
    expect(accessToken.rar).to.deep.equal(narrow);
    expect(refreshToken.rar).to.deep.equal(broad);
    expect(response.body.authorization_details).to.deep.equal(accessToken.rar);

    const payload = JSON.parse(Buffer.from(
      response.body.access_token.split('.')[1],
      'base64url',
    ));
    expect(payload.authorization_details).to.deep.equal(narrow);

    resetRarState();
    const refreshResponse = await this.agent.post('/token')
      .auth('client', 'secret')
      .type('form')
      .send({
        grant_type: 'refresh_token',
        refresh_token: response.body.refresh_token,
        resource: JWT_API,
        authorization_details: JSON.stringify(narrow),
      })
      .expect(200);

    expect(rarState.accessTokenCalls).to.have.lengthOf(1);
    expect(rarState.accessTokenCalls[0].grantType).to.equal('refresh_token');
    expect(rarState.accessTokenCalls[0].source).to.have.property('kind', 'RefreshToken');
    expect(rarState.accessTokenCalls[0].source.rar).to.deep.equal(broad);
    expect(refreshResponse.body.authorization_details).to.deep.equal(narrow);
  });

  it('supports device-code RAR and device-origin refresh narrowing', async function () {
    let code;
    let userCode;
    await this.agent.post('/device/auth')
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

    this.getSession().state = { secret: 'foo' };

    let location;
    await this.agent.post('/device')
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

    await this.agent.post(location)
      .send({ prompt: 'consent' })
      .type('form')
      .expect(303)
      .expect((response) => {
        ({ location } = response.headers);
      });

    await this.agent.get(new URL(location, this.provider.issuer).pathname)
      .expect(200);

    const deviceCode = await this.provider.DeviceCode.find(code);
    expect(deviceCode.rar).to.deep.equal(broad);
    expect(rarState.grantSourceCalls).to.have.lengthOf(1);
    expect(rarState.grantSourceCalls[0]).to.have.property('kind', 'DeviceCode');
    expect(rarState.grantSourceCalls[0].rar).to.deep.equal(broad);

    resetRarState();

    const accessTokenSaved = sinon.spy();
    const refreshTokenSaved = sinon.spy();
    this.provider.once('access_token.saved', accessTokenSaved);
    this.provider.once('refresh_token.saved', refreshTokenSaved);

    const response = await this.agent.post('/token')
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

    expect(rarState.accessTokenCalls).to.have.lengthOf(1);
    expect(rarState.accessTokenCalls[0].grantType).to.equal(DEVICE_GRANT);
    expect(rarState.accessTokenCalls[0].source).to.have.property('kind', 'DeviceCode');
    expect(accessTokenSaved.firstCall.args[0].rar).to.deep.equal(narrow);
    expect(refreshTokenSaved.firstCall.args[0].rar).to.deep.equal(broad);
    expect(response.body.authorization_details).to.deep.equal(narrow);

    resetRarState();
    const refreshResponse = await this.agent.post('/token')
      .auth('client', 'secret')
      .type('form')
      .send({
        grant_type: 'refresh_token',
        refresh_token: response.body.refresh_token,
        resource: API,
        authorization_details: JSON.stringify(narrow),
      })
      .expect(200);

    expect(rarState.accessTokenCalls).to.have.lengthOf(1);
    expect(rarState.accessTokenCalls[0].grantType).to.equal('refresh_token');
    expect(rarState.accessTokenCalls[0].source.rar).to.deep.equal(broad);
    expect(refreshResponse.body.authorization_details).to.deep.equal(narrow);
  });

  it('clears inherited RAR when access-token policy returns undefined', async function () {
    const grant = new this.provider.Grant({
      accountId: 'account',
      clientId: 'client',
    });
    grant.addOIDCScope('api:read');
    for (const detail of broad) grant.addRar(detail);
    await grant.save();
    const deviceCode = new this.provider.DeviceCode({
      accountId: 'account',
      clientId: 'client',
      grantId: grant.jti,
      rar: broad,
      scope: 'api:read',
    });
    const code = await deviceCode.save();
    const accessTokenSaved = sinon.spy();
    this.provider.once('access_token.saved', accessTokenSaved);
    rarState.clearAccessTokenResult = true;

    const response = await this.agent.post('/token')
      .auth('client', 'secret')
      .type('form')
      .send({
        client_id: 'client',
        device_code: code,
        grant_type: DEVICE_GRANT,
      })
      .expect(200);

    expect(rarState.accessTokenCalls).to.have.lengthOf(1);
    expect(rarState.accessTokenCalls[0].resource).to.be.undefined;
    expect(rarState.accessTokenCalls[0].source.rar).to.deep.equal(broad);
    expect(accessTokenSaved.firstCall.args[0].rar).to.be.undefined;
    expect(response.body).not.to.have.property('authorization_details');
  });

  it('supports CIBA RAR and passes the exact grant type', async function () {
    const grant = await grantWithRar.call(this);
    const request = new this.provider.BackchannelAuthenticationRequest({
      accountId: 'account',
      clientId: 'client',
      resource: API,
      scope: 'api:read',
    });
    await this.provider.backchannelResult(request, grant, { rar: broad });

    const response = await this.agent.post('/token')
      .auth('client', 'secret')
      .type('form')
      .send({
        auth_req_id: request.jti,
        grant_type: CIBA_GRANT,
        resource: API,
        authorization_details: JSON.stringify(narrow),
      })
      .expect(200);

    expect(rarState.accessTokenCalls).to.have.lengthOf(1);
    expect(rarState.accessTokenCalls[0].grantType).to.equal(CIBA_GRANT);
    expect(rarState.accessTokenCalls[0].source)
      .to.have.property('kind', 'BackchannelAuthenticationRequest');
    expect(response.body.authorization_details).to.deep.equal(narrow);
  });

  it('passes each introspectable RAR token kind to the introspection policy', async function () {
    const client = await this.provider.Client.find('client');
    const common = {
      client,
      rar: narrow,
      scope: 'api:read',
    };
    const tokens = [
      new this.provider.AccessToken({
        ...common,
        accountId: 'account',
        aud: API,
        grantId: this.getGrantId(),
      }),
      new this.provider.ClientCredentials({
        ...common,
        aud: API,
      }),
      new this.provider.RefreshToken({
        ...common,
        accountId: 'account',
        grantId: this.getGrantId(),
      }),
    ];

    for (const token of tokens) {
      const value = await token.save();
      resetRarState();

      await this.agent.post('/token/introspection')
        .auth('client', 'secret')
        .type('form')
        .send({ token: value })
        .expect(200)
        .expect((introspection) => {
          expect(introspection.body).to.have.property('active', true);
          expect(introspection.body.authorization_details).to.deep.equal(narrow);
        });

      expect(rarState.introspectionCalls).to.have.lengthOf(1);
      const [call] = rarState.introspectionCalls;
      expect(call.client).to.have.property('clientId', 'client');
      expect(call.token).to.be.instanceOf(token.constructor);
      expect(call.token).to.have.property('kind', token.kind);
      expect(call.token.rar).to.deep.equal(narrow);
    }
  });

  it('allows the introspection policy to filter stored RAR by token audience', async function () {
    const authorizationDetails = [{
      ...narrow[0],
      locations: [API],
    }, {
      ...broad[0],
      locations: [JWT_API],
    }];
    const response = await this.agent.post('/token')
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

    await this.agent.post('/token/introspection')
      .auth('client', 'secret')
      .type('form')
      .send({ token: response.body.access_token })
      .expect(200)
      .expect((introspection) => {
        expect(introspection.body).to.have.property('active', true);
        expect(introspection.body.authorization_details).to.deep.equal([authorizationDetails[0]]);
      });

    expect(rarState.introspectionCalls).to.have.lengthOf(1);
    const [call] = rarState.introspectionCalls;
    expect(call.client).to.have.property('clientId', 'client');
    expect(call.token).to.be.instanceOf(this.provider.ClientCredentials);
    expect(call.token).to.have.property('aud', API);
    expect(call.token).to.have.property('kind', 'ClientCredentials');
    expect(call.token.rar).to.deep.equal(authorizationDetails);
  });

  it('normalizes an empty introspection policy result to an omitted member', async function () {
    const token = new this.provider.ClientCredentials({
      aud: API,
      client: await this.provider.Client.find('client'),
      rar: narrow,
      scope: 'api:read',
    });
    const value = await token.save();
    rarState.emptyIntrospectionResult = true;

    await this.agent.post('/token/introspection')
      .auth('client', 'secret')
      .type('form')
      .send({ token: value })
      .expect(200)
      .expect((introspection) => {
        expect(introspection.body).to.have.property('active', true);
        expect(introspection.body).not.to.have.property('authorization_details');
      });

    expect(rarState.introspectionCalls).to.have.lengthOf(1);
    expect(rarState.introspectionCalls[0].token.rar).to.deep.equal(narrow);
  });

  it('treats malformed introspection policy output as a server configuration error', async function () {
    const token = new this.provider.ClientCredentials({
      aud: API,
      client: await this.provider.Client.find('client'),
      rar: narrow,
      scope: 'api:read',
    });
    const value = await token.save();
    const serverError = sinon.spy();
    this.provider.once('server_error', serverError);
    rarState.invalidIntrospectionResult = true;

    await this.agent.post('/token/introspection')
      .auth('client', 'secret')
      .type('form')
      .send({ token: value })
      .expect(500)
      .expect({
        error: 'server_error',
        error_description: 'oops! something went wrong',
      });

    expect(rarState.introspectionCalls).to.have.lengthOf(1);
    expect(serverError).to.have.property('calledOnce', true);
    expect(serverError.firstCall.args[1]).to.be.instanceOf(TypeError);
    expect(serverError.firstCall.args[1].message).to.equal(
      'authorization details policy result members should be a JSON object',
    );
  });
});
