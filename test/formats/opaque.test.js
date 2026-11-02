import { describe, before, afterEach, it } from 'node:test';
import assert from 'node:assert/strict';
import { createSandbox } from 'sinon';

import epochTime from '../../lib/helpers/epoch_time.js';
import bootstrap from '../test_helper.js';

const sinon = createSandbox();

const { spy, match: { string, number }, assert: sinonAssert } = sinon;

describe('opaque storage', () => {
  const fixture = {};

  before(bootstrap(import.meta.url, fixture), { timeout: 3000 });
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

  afterEach(() => sinon.restore(), { timeout: 3000 });

  it('for AccessToken', { timeout: 3000 }, async () => {
    const kind = 'AccessToken';
    const upsert = spy(fixture.TestAdapter.for('AccessToken'), 'upsert');
    const client = await fixture.provider.Client.find(clientId);
    const token = new fixture.provider.AccessToken({ client, ...fullPayload });
    await token.save();

    assert.equal(upsert.getCall(0).args[0].length, 43);
    sinonAssert.calledWith(upsert, string, {
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

  it('for AccessToken extraTokenClaims gets assigned upon save()', { timeout: 3000 }, async () => {
    const client = await fixture.provider.Client.find(clientId);
    const token = new fixture.provider.AccessToken({ client, ...fullPayload, extra: undefined });
    assert.deepEqual(token.extra, undefined);
    await token.save();
    assert.deepEqual(token.extra, extra);
  });

  it('for AuthorizationCode', { timeout: 3000 }, async () => {
    const kind = 'AuthorizationCode';
    const upsert = spy(fixture.TestAdapter.for('AuthorizationCode'), 'upsert');
    const client = await fixture.provider.Client.find(clientId);
    const token = new fixture.provider.AuthorizationCode({ client, ...fullPayload });
    await token.save();

    assert.equal(upsert.getCall(0).args[0].length, 43);
    sinonAssert.calledWith(upsert, string, {
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

  it('for DeviceCode', { timeout: 3000 }, async () => {
    const kind = 'DeviceCode';
    const upsert = spy(fixture.TestAdapter.for('DeviceCode'), 'upsert');
    const client = await fixture.provider.Client.find(clientId);
    const token = new fixture.provider.DeviceCode({ client, ...fullPayload });
    await token.save();

    assert.equal(upsert.getCall(0).args[0].length, 43);
    sinonAssert.calledWith(upsert, string, {
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

  it('for BackchannelAuthenticationRequest', { timeout: 3000 }, async () => {
    const kind = 'BackchannelAuthenticationRequest';
    const upsert = spy(fixture.TestAdapter.for('BackchannelAuthenticationRequest'), 'upsert');
    const client = await fixture.provider.Client.find(clientId);
    const token = new fixture.provider.BackchannelAuthenticationRequest({ client, ...fullPayload });
    await token.save();

    assert.equal(upsert.getCall(0).args[0].length, 43);
    sinonAssert.calledWith(upsert, string, {
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

  it('for RefreshToken', { timeout: 3000 }, async () => {
    const kind = 'RefreshToken';
    const upsert = spy(fixture.TestAdapter.for('RefreshToken'), 'upsert');
    const client = await fixture.provider.Client.find(clientId);
    const token = new fixture.provider.RefreshToken({ client, ...fullPayload });
    await token.save();

    assert.equal(upsert.getCall(0).args[0].length, 43);
    sinonAssert.calledWith(upsert, string, {
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

  it('for ClientCredentials', { timeout: 3000 }, async () => {
    const kind = 'ClientCredentials';
    const upsert = spy(fixture.TestAdapter.for('ClientCredentials'), 'upsert');
    const client = await fixture.provider.Client.find(clientId);
    const token = new fixture.provider.ClientCredentials({ client, ...fullPayload });
    await token.save();

    assert.equal(upsert.getCall(0).args[0].length, 43);
    sinonAssert.calledWith(upsert, string, {
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

  it('for ClientCredentials extraTokenClaims gets assigned upon save()', { timeout: 3000 }, async () => {
    const client = await fixture.provider.Client.find(clientId);
    const token = new fixture.provider.ClientCredentials({ client, ...fullPayload, extra: undefined });
    assert.deepEqual(token.extra, undefined);
    await token.save();
    assert.deepEqual(token.extra, extra);
  });

  it('for InitialAccessToken', { timeout: 3000 }, async () => {
    const kind = 'InitialAccessToken';
    const upsert = spy(fixture.TestAdapter.for('InitialAccessToken'), 'upsert');
    const token = new fixture.provider.InitialAccessToken({
      clientId,
      expiresIn: 100,
      ...fullPayload,
    });
    await token.save();

    assert.equal(upsert.getCall(0).args[0].length, 43);
    sinonAssert.calledWith(upsert, string, {
      exp: number,
      iat: number,
      jti: upsert.getCall(0).args[0],
      kind,
      policies,
    });
    assert.ok(!('clientId' in Object(upsert.getCall(0).args[1])));
  });

  it('retains allowed undefined properties in memory but omits them from storage', { timeout: 3000 }, async () => {
    const upsert = spy(fixture.TestAdapter.for('AccessToken'), 'upsert');
    const token = new fixture.provider.AccessToken({
      scope: undefined,
      unsupported: 'value',
    });

    ((actual) => { assert.ok(Object.hasOwn(actual, 'scope')); assert.equal(actual.scope, undefined); })(token);
    assert.ok(!('unsupported' in Object(token)));

    await token.save();
    assert.ok(!('scope' in Object(upsert.getCall(0).args[1])));
  });

  it('filters model payloads without invoking unknown accessors or prototypes', { timeout: 3000 }, async () => {
    const Parent = fixture.provider.Session;
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
    assert.ok(!(Object.hasOwn(model, 'accountId')));
    ((actual) => { assert.ok(!('jti' in Object(actual) && actual.jti === 'inherited-jti')); })(model);
    ((actual) => { assert.ok(!('kind' in Object(actual) && actual.kind === 'AccessToken')); })(model);
    ((actual) => { assert.ok('seen' in Object(actual)); assert.equal(actual.seen, 'setter value'); })(model);
    assert.ok(!(Object.hasOwn(model, 'custom')));
    ((actual) => { assert.ok(Object.hasOwn(actual, '__proto__')); assert.deepEqual(actual.__proto__, { polluted: true }); })(model);
    assert.equal(Object.getPrototypeOf(model), Model.prototype);

    model.format = 'opaque';
    const { payload } = await model.getValueAndPayload();
    ((actual) => { assert.ok(Object.hasOwn(actual, '__proto__')); assert.deepEqual(actual.__proto__, { polluted: true }); })(payload);
    assert.equal(Object.getPrototypeOf(payload), Object.prototype);

    assert.throws(() => new Parent(null), (error) => { assert.ok(error instanceof TypeError); assert.ok(error.message.includes('invalid model payload')); return true; });
  });

  it('resolves payload properties once per concrete model', { timeout: 3000 }, async () => {
    let getterCalls = 0;
    const Parent = fixture.provider.AccessToken;
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

    ((actual) => { assert.ok('custom' in Object(actual)); assert.equal(actual.custom, 'first'); })(firstPayload);
    ((actual) => { assert.ok('custom' in Object(actual)); assert.equal(actual.custom, 'second'); })(secondPayload);
    assert.equal(getterCalls, 1);
  });

  it('for RegistrationAccessToken', { timeout: 3000 }, async () => {
    const kind = 'RegistrationAccessToken';
    const upsert = spy(fixture.TestAdapter.for('RegistrationAccessToken'), 'upsert');
    const client = await fixture.provider.Client.find(clientId);
    const token = new fixture.provider.RegistrationAccessToken({
      client,
      expiresIn: 100,
      ...fullPayload,
    });
    await token.save();

    assert.equal(upsert.getCall(0).args[0].length, 43);
    sinonAssert.calledWith(upsert, string, {
      clientId,
      kind,
      policies,
      jti: upsert.getCall(0).args[0],
      iat: number,
      exp: number,
    });
  });
});
