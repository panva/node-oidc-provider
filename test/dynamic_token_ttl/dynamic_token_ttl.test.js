const url = require('url');

const { expect } = require('chai');
const sinon = require('sinon');
const cloneDeep = require('lodash/cloneDeep');

const bootstrap = require('../test_helper');
const JWT = require('../../lib/helpers/jwt');

describe('dynamic ttl', () => {
  before(bootstrap(__dirname));
  bootstrap.skipConsent();
  before(function () {
    this.prev = cloneDeep(i(this.provider).configuration('ttl'));
  });
  afterEach(function () {
    i(this.provider).configuration().ttl = this.prev;
  });
  before(function () { return this.login(); });

  it('client credentials', async function () {
    const ClientCredentials = sinon.fake.returns(123);
    i(this.provider).configuration('ttl').ClientCredentials = ClientCredentials;

    await this.agent.post('/token')
      .send({
        client_id: 'client',
        grant_type: 'client_credentials',
      })
      .type('form')
      .expect(200)
      .expect(({ body: { expires_in } }) => {
        expect(expires_in).to.eql(123);
      });

    expect(ClientCredentials).to.have.property('calledOnce', true);
    expect(ClientCredentials.args[0][1]).to.be.an.instanceof(this.provider.ClientCredentials);
    expect(ClientCredentials.args[0][2]).to.be.an.instanceof(this.provider.Client);
  });

  it('device flow init', async function () {
    const DeviceCode = sinon.fake.returns(123);
    i(this.provider).configuration('ttl').DeviceCode = DeviceCode;

    let device_code;
    await this.agent.post('/device/auth')
      .send({
        client_id: 'client',
        scope: 'openid offline_access',
        prompt: 'consent',
      })
      .type('form')
      .expect(200)
      .expect(({ body: { expires_in, device_code: dc } }) => {
        expect(expires_in).to.eql(123);
        device_code = dc;
      });

    expect(DeviceCode).to.have.property('calledOnce', true);
    expect(DeviceCode.args[0][1]).to.be.an.instanceof(this.provider.DeviceCode);
    expect(DeviceCode.args[0][2]).to.be.an.instanceof(this.provider.Client);

    this.TestAdapter.for('DeviceCode').syncUpdate(this.getTokenJti(device_code), {
      scope: 'openid offline_access',
      accountId: 'account',
    });

    const IdToken = sinon.fake.returns(123);
    const AccessToken = sinon.fake.returns(1234);
    const RefreshToken = sinon.fake.returns(12345);
    i(this.provider).configuration('ttl').IdToken = IdToken;
    i(this.provider).configuration('ttl').AccessToken = AccessToken;
    i(this.provider).configuration('ttl').RefreshToken = RefreshToken;

    await this.agent.post('/token')
      .send({
        client_id: 'client',
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        device_code,
      })
      .type('form')
      .expect(200);

    expect(IdToken).to.have.property('calledOnce', true);
    expect(IdToken.args[0][1]).to.be.an.instanceof(this.provider.IdToken);
    expect(IdToken.args[0][2]).to.be.an.instanceof(this.provider.Client);

    expect(AccessToken).to.have.property('calledOnce', true);
    expect(AccessToken.args[0][1]).to.be.an.instanceof(this.provider.AccessToken);
    expect(AccessToken.args[0][2]).to.be.an.instanceof(this.provider.Client);

    expect(RefreshToken).to.have.property('calledOnce', true);
    expect(RefreshToken.args[0][1]).to.be.an.instanceof(this.provider.RefreshToken);
    expect(RefreshToken.args[0][2]).to.be.an.instanceof(this.provider.Client);
  });

  it('authorization flow returned tokens', async function () {
    const IdToken = sinon.fake.returns(123);
    const AccessToken = sinon.fake.returns(1234);
    const AuthorizationCode = sinon.fake.returns(12);
    i(this.provider).configuration('ttl').IdToken = IdToken;
    i(this.provider).configuration('ttl').AccessToken = AccessToken;
    i(this.provider).configuration('ttl').AuthorizationCode = AuthorizationCode;

    const auth = new this.AuthorizationRequest({
      response_type: 'code id_token token',
      scope: 'openid',
    });

    await this.wrap({ route: '/auth', verb: 'get', auth })
      .expect(302)
      .expect(auth.validateFragment)
      .expect(({ headers: { location } }) => {
        const { query: { expires_in, id_token } } = url.parse(location, true);
        expect(expires_in).to.eql('1234');
        const { payload: { iat, exp } } = JWT.decode(id_token);
        expect(exp - iat).to.eql(123);
      });

    expect(IdToken).to.have.property('calledOnce', true);
    expect(IdToken.args[0][1]).to.be.an.instanceof(this.provider.IdToken);
    expect(IdToken.args[0][2]).to.be.an.instanceof(this.provider.Client);

    expect(AccessToken).to.have.property('calledOnce', true);
    expect(AccessToken.args[0][1]).to.be.an.instanceof(this.provider.AccessToken);
    expect(AccessToken.args[0][2]).to.be.an.instanceof(this.provider.Client);

    expect(AuthorizationCode).to.have.property('calledOnce', true);
    expect(AuthorizationCode.args[0][1]).to.be.an.instanceof(this.provider.AuthorizationCode);
    expect(AuthorizationCode.args[0][2]).to.be.an.instanceof(this.provider.Client);
  });

  it('authorization code', async function () {
    const IdToken = sinon.fake.returns(123);
    const AccessToken = sinon.fake.returns(1234);
    const RefreshToken = sinon.fake.returns(12345);
    i(this.provider).configuration('ttl').IdToken = IdToken;
    i(this.provider).configuration('ttl').AccessToken = AccessToken;
    i(this.provider).configuration('ttl').RefreshToken = RefreshToken;

    const auth = new this.AuthorizationRequest({
      response_type: 'code',
      scope: 'openid offline_access',
      prompt: 'consent',
    });

    let code;

    await this.wrap({ route: '/auth', verb: 'get', auth })
      .expect(302)
      .expect(({ headers: { location } }) => {
        ({ query: { code } } = url.parse(location, true));
      });

    await this.agent.post('/token')
      .send({
        client_id: 'client',
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://rp.example.com/cb',
      })
      .type('form')
      .expect(200);

    expect(IdToken).to.have.property('calledOnce', true);
    expect(IdToken.args[0][1]).to.be.an.instanceof(this.provider.IdToken);
    expect(IdToken.args[0][2]).to.be.an.instanceof(this.provider.Client);

    expect(AccessToken).to.have.property('calledOnce', true);
    expect(AccessToken.args[0][1]).to.be.an.instanceof(this.provider.AccessToken);
    expect(AccessToken.args[0][2]).to.be.an.instanceof(this.provider.Client);

    expect(RefreshToken).to.have.property('calledOnce', true);
    expect(RefreshToken.args[0][1]).to.be.an.instanceof(this.provider.RefreshToken);
    expect(RefreshToken.args[0][2]).to.be.an.instanceof(this.provider.Client);
  });

  it('refreshed tokens', async function () {
    const auth = new this.AuthorizationRequest({
      response_type: 'code',
      scope: 'openid offline_access',
      prompt: 'consent',
    });

    let code;

    await this.wrap({ route: '/auth', verb: 'get', auth })
      .expect(302)
      .expect(({ headers: { location } }) => {
        ({ query: { code } } = url.parse(location, true));
      });

    let refresh_token;

    await this.agent.post('/token')
      .send({
        client_id: 'client',
        grant_type: 'authorization_code',
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
    i(this.provider).configuration('ttl').IdToken = IdToken;
    i(this.provider).configuration('ttl').AccessToken = AccessToken;
    i(this.provider).configuration('ttl').RefreshToken = RefreshToken;

    await this.agent.post('/token')
      .send({
        client_id: 'client',
        grant_type: 'refresh_token',
        refresh_token,
        redirect_uri: 'https://rp.example.com/cb',
      })
      .type('form')
      .expect(200);

    expect(IdToken).to.have.property('calledOnce', true);
    expect(IdToken.args[0][1]).to.be.an.instanceof(this.provider.IdToken);
    expect(IdToken.args[0][2]).to.be.an.instanceof(this.provider.Client);

    expect(AccessToken).to.have.property('calledOnce', true);
    expect(AccessToken.args[0][1]).to.be.an.instanceof(this.provider.AccessToken);
    expect(AccessToken.args[0][2]).to.be.an.instanceof(this.provider.Client);

    expect(RefreshToken).to.have.property('calledOnce', true);
    expect(RefreshToken.args[0][1]).to.be.an.instanceof(this.provider.RefreshToken);
    expect(RefreshToken.args[0][2]).to.be.an.instanceof(this.provider.Client);
  });
});
