import { createSandbox } from 'sinon';
import { expect } from 'chai';

import epochTime from '../../lib/helpers/epoch_time.js';
import bootstrap from '../test_helper.js';

const sinon = createSandbox();

const { spy, match: { string, number }, assert } = sinon;

describe('opaque storage', () => {
  before(bootstrap(import.meta.url));
  const accountId = 'account';
  const claims = {};
  const clientId = 'client';
  const grantId = 'grantid';
  const scope = 'openid';
  const sid = 'sid';
  const consumed = true;
  const acr = 'acr';
  const amr = ['amr'];
  const authTime = epochTime();
  const nonce = 'nonce';
  const redirectUri = 'https://rp.example.com/cb';
  const codeChallenge = 'codeChallenge';
  const codeChallengeMethod = 'codeChallengeMethod';
  const aud = [clientId, 'foo'];
  const gty = 'foo';
  const error = 'access_denied';
  const errorDescription = 'resource owner denied access';
  const params = { foo: 'bar' };
  const userCode = '1384-3217';
  const deviceInfo = { foo: 'bar' };
  const inFlight = true;
  const s256 = '_gPMqAT8BELhXwBa2nIT0OvdWtQCiF_g09nAyHhgCe0';
  const resource = 'urn:foo:bar';
  const policies = ['foo'];
  const sessionUid = 'foo';
  const expiresWithSession = false;
  const iiat = epochTime();
  const rotations = 1;
  const extra = { foo: 'bar' };
  const dpopJkt = 'cbaZgHZazjgQq0Q2-Hy_o2-OCDpPu02S30lNhTsNU1Q';

  // TODO: add Session and Interaction

  const fullPayload = {
    accountId, claims, grantId, scope, sid, consumed, acr, amr, authTime, nonce,
    redirectUri, codeChallenge, codeChallengeMethod, aud, error, errorDescription, params,
    userCode, deviceInfo, gty, resource, policies, sessionUid, expiresWithSession,
    'x5t#S256': s256, inFlight, iiat, rotations, extra, jkt: s256, dpopJkt,
  };

  afterEach(sinon.restore);

  it('for AccessToken', async function () {
    const kind = 'AccessToken';
    const upsert = spy(this.TestAdapter.for('AccessToken'), 'upsert');
    const client = await this.provider.Client.find(clientId);
    const token = new this.provider.AccessToken({ client, ...fullPayload });
    await token.save();

    expect(upsert.getCall(0).args[0]).to.have.lengthOf(43);
    assert.calledWith(upsert, string, {
      accountId,
      aud,
      claims,
      clientId,
      exp: number,
      grantId,
      gty,
      iat: number,
      jti: upsert.getCall(0).args[0],
      kind,
      scope,
      sid,
      'x5t#S256': s256,
      jkt: s256,
      sessionUid,
      expiresWithSession,
      extra,
    });
  });

  it('for AccessToken extraTokenClaims gets assigned upon save()', async function () {
    const client = await this.provider.Client.find(clientId);
    const token = new this.provider.AccessToken({ client, ...fullPayload, extra: undefined });
    expect(token.extra).to.eql(undefined);
    await token.save();
    expect(token.extra).to.eql(extra);
  });

  it('for AuthorizationCode', async function () {
    const kind = 'AuthorizationCode';
    const upsert = spy(this.TestAdapter.for('AuthorizationCode'), 'upsert');
    const client = await this.provider.Client.find(clientId);
    const token = new this.provider.AuthorizationCode({ client, ...fullPayload });
    await token.save();

    expect(upsert.getCall(0).args[0]).to.have.lengthOf(43);
    assert.calledWith(upsert, string, {
      accountId,
      acr,
      amr,
      authTime,
      claims,
      clientId,
      codeChallenge,
      codeChallengeMethod,
      consumed,
      exp: number,
      grantId,
      iat: number,
      jti: upsert.getCall(0).args[0],
      kind,
      nonce,
      redirectUri,
      resource,
      scope,
      sid,
      sessionUid,
      expiresWithSession,
      dpopJkt,
    });
  });

  it('for DeviceCode', async function () {
    const kind = 'DeviceCode';
    const upsert = spy(this.TestAdapter.for('DeviceCode'), 'upsert');
    const client = await this.provider.Client.find(clientId);
    const token = new this.provider.DeviceCode({ client, ...fullPayload });
    await token.save();

    expect(upsert.getCall(0).args[0]).to.have.lengthOf(43);
    assert.calledWith(upsert, string, {
      accountId,
      acr,
      amr,
      authTime,
      claims,
      clientId,
      consumed,
      deviceInfo,
      error,
      errorDescription,
      exp: number,
      grantId,
      iat: number,
      jti: upsert.getCall(0).args[0],
      kind,
      nonce,
      params,
      resource,
      scope,
      sid,
      userCode,
      sessionUid,
      expiresWithSession,
      inFlight,
    });
  });

  it('for BackchannelAuthenticationRequest', async function () {
    const kind = 'BackchannelAuthenticationRequest';
    const upsert = spy(this.TestAdapter.for('BackchannelAuthenticationRequest'), 'upsert');
    const client = await this.provider.Client.find(clientId);
    const token = new this.provider.BackchannelAuthenticationRequest({ client, ...fullPayload });
    await token.save();

    expect(upsert.getCall(0).args[0]).to.have.lengthOf(43);
    assert.calledWith(upsert, string, {
      accountId,
      acr,
      amr,
      authTime,
      claims,
      clientId,
      consumed,
      error,
      errorDescription,
      exp: number,
      grantId,
      iat: number,
      jti: upsert.getCall(0).args[0],
      kind,
      nonce,
      params,
      resource,
      scope,
      sid,
      sessionUid,
      expiresWithSession,
    });
  });

  it('for RefreshToken', async function () {
    const kind = 'RefreshToken';
    const upsert = spy(this.TestAdapter.for('RefreshToken'), 'upsert');
    const client = await this.provider.Client.find(clientId);
    const token = new this.provider.RefreshToken({ client, ...fullPayload });
    await token.save();

    expect(upsert.getCall(0).args[0]).to.have.lengthOf(43);
    assert.calledWith(upsert, string, {
      accountId,
      acr,
      amr,
      authTime,
      claims,
      iiat,
      rotations,
      clientId,
      consumed,
      exp: number,
      grantId,
      gty,
      iat: number,
      jti: upsert.getCall(0).args[0],
      kind,
      nonce,
      resource,
      scope,
      sid,
      'x5t#S256': s256,
      jkt: s256,
      sessionUid,
      expiresWithSession,
    });
  });

  it('for ClientCredentials', async function () {
    const kind = 'ClientCredentials';
    const upsert = spy(this.TestAdapter.for('ClientCredentials'), 'upsert');
    const client = await this.provider.Client.find(clientId);
    const token = new this.provider.ClientCredentials({ client, ...fullPayload });
    await token.save();

    expect(upsert.getCall(0).args[0]).to.have.lengthOf(43);
    assert.calledWith(upsert, string, {
      aud,
      clientId,
      exp: number,
      iat: number,
      jti: upsert.getCall(0).args[0],
      kind,
      scope,
      'x5t#S256': s256,
      jkt: s256,
      extra,
    });
  });

  it('for ClientCredentials extraTokenClaims gets assigned upon save()', async function () {
    const client = await this.provider.Client.find(clientId);
    const token = new this.provider.ClientCredentials({ client, ...fullPayload, extra: undefined });
    expect(token.extra).to.eql(undefined);
    await token.save();
    expect(token.extra).to.eql(extra);
  });

  it('for InitialAccessToken', async function () {
    const kind = 'InitialAccessToken';
    const upsert = spy(this.TestAdapter.for('InitialAccessToken'), 'upsert');
    const token = new this.provider.InitialAccessToken({
      clientId,
      expiresIn: 100,
      ...fullPayload,
    });
    await token.save();

    expect(upsert.getCall(0).args[0]).to.have.lengthOf(43);
    assert.calledWith(upsert, string, {
      exp: number,
      iat: number,
      jti: upsert.getCall(0).args[0],
      kind,
      policies,
    });
    expect(upsert.getCall(0).args[1]).not.to.have.property('clientId');
  });

  it('retains allowed undefined properties in memory but omits them from storage', async function () {
    const upsert = spy(this.TestAdapter.for('AccessToken'), 'upsert');
    const token = new this.provider.AccessToken({
      scope: undefined,
      unsupported: 'value',
    });

    expect(token).to.have.own.property('scope', undefined);
    expect(token).not.to.have.property('unsupported');

    await token.save();
    expect(upsert.getCall(0).args[1]).not.to.have.property('scope');
  });

  it('filters model payloads without invoking unknown accessors or prototypes', async function () {
    const Parent = this.provider.Session;
    class Model extends Parent {
      static get IN_PAYLOAD() {
        return [...Parent.IN_PAYLOAD, 'custom', '__proto__'];
      }

      set custom(value) {
        this.seen = value;
      }
    }

    const input = Object.create({
      accountId,
      jti: 'inherited-jti',
      kind: 'AccessToken',
    });
    Object.defineProperties(input, {
      state: { enumerable: true, value: { own: true } },
      custom: { enumerable: true, value: 'setter value' },
      unsupported: {
        enumerable: true,
        get() {
          throw new Error('unknown property was read');
        },
      },
      [Symbol('unsupported')]: {
        enumerable: true,
        get() {
          throw new Error('unknown symbol was read');
        },
      },
    });
    Object.defineProperty(input, '__proto__', {
      enumerable: true,
      value: { polluted: true },
    });

    const model = new Model(input);
    expect(model).not.to.have.own.property('accountId');
    expect(model).not.to.have.property('jti', 'inherited-jti');
    expect(model).not.to.have.property('kind', 'AccessToken');
    expect(model).to.have.property('seen', 'setter value');
    expect(model).not.to.have.own.property('custom');
    expect(model).to.have.own.property('__proto__').that.eql({ polluted: true });
    expect(Object.getPrototypeOf(model)).to.equal(Model.prototype);

    model.format = 'opaque';
    const { payload } = await model.getValueAndPayload();
    expect(payload).to.have.own.property('__proto__').that.eql({ polluted: true });
    expect(Object.getPrototypeOf(payload)).to.equal(Object.prototype);

    expect(() => new Parent(null)).to.throw(TypeError, 'invalid model payload');
  });

  it('resolves payload properties once per concrete model', async function () {
    let getterCalls = 0;
    const Parent = this.provider.AccessToken;
    class Model extends Parent {
      static get IN_PAYLOAD() {
        getterCalls += 1;
        return [...Parent.IN_PAYLOAD, 'custom'];
      }
    }

    const first = new Model({ custom: 'first' });
    const second = new Model({ custom: 'second' });
    first.format = 'opaque';
    second.format = 'opaque';
    const { payload: firstPayload } = await first.getValueAndPayload();
    const { payload: secondPayload } = await second.getValueAndPayload();

    expect(firstPayload).to.have.property('custom', 'first');
    expect(secondPayload).to.have.property('custom', 'second');
    expect(getterCalls).to.equal(1);
  });

  it('for RegistrationAccessToken', async function () {
    const kind = 'RegistrationAccessToken';
    const upsert = spy(this.TestAdapter.for('RegistrationAccessToken'), 'upsert');
    const client = await this.provider.Client.find(clientId);
    const token = new this.provider.RegistrationAccessToken({
      client,
      expiresIn: 100,
      ...fullPayload,
    });
    await token.save();

    expect(upsert.getCall(0).args[0]).to.have.lengthOf(43);
    assert.calledWith(upsert, string, {
      clientId,
      kind,
      policies,
      jti: upsert.getCall(0).args[0],
      iat: number,
      exp: number,
    });
  });
});
