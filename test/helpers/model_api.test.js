import { strict as assert } from 'node:assert';

import { expect } from 'chai';
import { createSandbox } from 'sinon';

import Provider from '../../lib/index.js';
import epochTime from '../../lib/helpers/epoch_time.js';
import instance from '../../lib/helpers/weak_cache.js';

const base = ['iat', 'exp', 'jti', 'kind'];
const token = [...base, 'clientId'];
const auth = ['accountId', 'acr', 'amr', 'authTime', 'claims', 'nonce', 'resource', 'scope', 'sid'];
const session = ['sessionUid', 'expiresWithSession'];
const sender = ['x5t#S256', 'jkt'];
const payloads = {
  BaseModel: base,
  BaseToken: token,
  AccessToken: [
    ...token, 'gty', 'grantId', ...sender, ...session,
    'accountId', 'aud', 'rar', 'claims', 'extra', 'grantId', 'scope', 'sid',
  ],
  AuthorizationCode: [
    ...token, 'consumed', ...session, 'grantId', 'attestationJkt', ...auth,
    'codeChallenge', 'codeChallengeMethod', 'redirectUri', 'dpopJkt', 'rar',
  ],
  RefreshToken: [
    ...token, 'consumed', 'gty', 'grantId', ...sender, 'attestationJkt', ...session, ...auth,
    'rar', 'rotations', 'iiat',
  ],
  ClientCredentials: [...token, ...sender, 'aud', 'extra', 'rar', 'scope'],
  DeviceCode: [
    ...token, 'consumed', 'grantId', 'attestationJkt', ...session, ...auth,
    'error', 'errorDescription', 'params', 'rar', 'userCode', 'inFlight', 'deviceInfo',
  ],
  BackchannelAuthenticationRequest: [
    ...token, 'consumed', 'grantId', 'attestationJkt', ...session, ...auth,
    'error', 'errorDescription', 'params', 'rar',
  ],
  PreAuthorizedCode: [
    ...token, 'consumed', 'grantId', 'accountId', 'claims', 'rar', 'resource', 'scope', 'txCode',
  ],
  InitialAccessToken: [...base, 'policies'],
  RegistrationAccessToken: [...token, 'policies'],
  ReplayDetection: [...base, 'iss'],
  Grant: ['accountId', 'clientId', 'resources', 'openid', 'rejected', 'rar', ...token],
  PushedAuthorizationRequest: [...base, 'consumed', 'attestationJkt', 'request', 'dpopJkt', 'trusted'],
  Session: [...base, 'uid', 'acr', 'amr', 'accountId', 'loginTs', 'transient', 'state', 'authorizations'],
  Interaction: [
    ...base, 'session', 'params', 'prompt', 'result', 'returnTo', 'trusted', 'grantId',
    'lastSubmission', 'deviceCode', 'cid', 'parJti',
  ],
};

const grantBound = [
  'AccessToken', 'AuthorizationCode', 'RefreshToken', 'DeviceCode',
  'BackchannelAuthenticationRequest', 'PreAuthorizedCode',
];
const consumable = [
  'AuthorizationCode', 'RefreshToken', 'DeviceCode', 'BackchannelAuthenticationRequest',
  'PreAuthorizedCode', 'PushedAuthorizationRequest',
];
const attested = [
  'AuthorizationCode', 'RefreshToken', 'DeviceCode', 'BackchannelAuthenticationRequest',
  'PushedAuthorizationRequest',
];
const senderConstrained = ['AccessToken', 'RefreshToken', 'ClientCredentials'];
const capabilities = {
  consume: consumable,
  setAudience: ['AccessToken', 'ClientCredentials'],
  setThumbprint: senderConstrained,
  isSenderConstrained: senderConstrained,
  setAttestBinding: attested,
};

function setup() {
  return new Provider('https://op.example.com', {
    adapter() {
      const records = new Map();
      return {
        async upsert(id, payload) { records.set(id, structuredClone(payload)); },
        async find(id) { return structuredClone(records.get(id)); },
        async consume(id) { records.get(id).consumed = epochTime(); },
        async destroy(id) { records.delete(id); },
        async revokeByGrantId(grantId) {
          for (const [id, payload] of records) {
            if (payload.grantId === grantId) records.delete(id);
          }
        },
      };
    },
  });
}

function model(provider, name) {
  return provider[name] || instance(provider)[name];
}

describe('model API compatibility', () => {
  const sinon = createSandbox();
  let provider;

  beforeEach(() => { provider = setup(); });
  afterEach(() => sinon.restore());

  for (const [name, expected] of Object.entries(payloads)) {
    it(`${name} retains its payload field order and capabilities`, () => {
      const Model = model(provider, name);
      expect(Model.IN_PAYLOAD).to.eql(expected);
      for (const [method, models] of Object.entries(capabilities)) {
        expect(typeof Model.prototype[method], method).to.equal(
          models.includes(name) ? 'function' : 'undefined',
        );
      }
      expect(typeof Model.revokeByGrantId).to.equal(
        grantBound.includes(name) ? 'function' : 'undefined',
      );
    });
  }

  it('keeps model constructors, adapters, configuration, and events isolated per provider', async () => {
    const second = setup();
    for (const name of Object.keys(payloads)) {
      const First = model(provider, name);
      const Second = model(second, name);
      expect(First).not.to.equal(Second);
      expect(First.adapter).not.to.equal(Second.adapter);
      expect(new First().adapter).to.equal(First.adapter);
    }

    instance(provider).configuration.ttl.RefreshToken = 60;
    instance(second).configuration.ttl.RefreshToken = 120;
    const firstSaved = sinon.spy();
    const secondSaved = sinon.spy();
    provider.on('refresh_token.saved', firstSaved);
    second.on('refresh_token.saved', secondSaved);
    const first = new provider.RefreshToken({ jti: 'same-id' });
    const other = new second.RefreshToken({ jti: 'same-id' });
    await first.save();
    expect(await second.RefreshToken.find('same-id')).to.be.undefined;
    expect(first.expiration).to.equal(60);
    expect(other.expiration).to.equal(120);
    sinon.assert.calledOnceWithExactly(firstSaved, first);
    sinon.assert.notCalled(secondSaved);
    await other.save();
    sinon.assert.calledOnceWithExactly(secondSaved, other);
    sinon.assert.calledOnce(firstSaved);
  });

  it('persists subclass payload fields and instantiates the subclass on lookup', async () => {
    const Parent = provider.AuthorizationCode;
    class CustomCode extends Parent {
      static get IN_PAYLOAD() { return [...Parent.IN_PAYLOAD, 'custom']; }
    }

    const code = new CustomCode({ expiresIn: 60, custom: { value: 'retained' }, omitted: true });
    expect(code).not.to.have.property('omitted');
    const value = await code.save();
    const stored = await CustomCode.adapter.find(value);
    expect(stored).to.include({ kind: 'CustomCode', jti: value });
    expect(stored.custom).to.eql({ value: 'retained' });
    expect(await CustomCode.find(value)).to.be.instanceOf(CustomCode)
      .and.have.deep.property('custom', { value: 'retained' });
    expect(await provider.AuthorizationCode.find(value)).to.be.undefined;
  });

  for (const [operation, event] of [['save', 'saved'], ['consume', 'consumed'], ['destroy', 'destroyed']]) {
    it(`emits ${event} only after the adapter operation completes`, async () => {
      const code = new provider.AuthorizationCode({ jti: 'code', expiresIn: 60 });
      const adapterMethod = operation === 'save' ? 'upsert' : operation;
      let start;
      let finish;
      const started = new Promise((resolve) => { start = resolve; });
      const completed = new Promise((resolve) => { finish = resolve; });
      const adapter = sinon.stub(code.adapter, adapterMethod).callsFake(() => {
        start();
        return completed;
      });
      const emitted = sinon.spy();
      provider.on(`authorization_code.${event}`, emitted);

      const pending = code[operation]();
      await started;
      sinon.assert.notCalled(emitted);
      expect(adapter.firstCall.args[0]).to.equal('code');
      finish();
      await pending;
      sinon.assert.calledOnceWithExactly(emitted, code);

      emitted.resetHistory();
      const error = new Error('adapter failed');
      adapter.rejects(error);
      await assert.rejects(code[operation](), (err) => err === error);
      sinon.assert.notCalled(emitted);
    });
  }

  it('consumes stored tokens without mutating the issued instance', async () => {
    const code = new provider.AuthorizationCode({ expiresIn: 60, grantId: 'grant' });
    const value = await code.save();
    await code.consume();
    expect(code).not.to.have.property('consumed');
    expect(code.isValid).to.be.true;
    const consumed = await provider.AuthorizationCode.find(value);
    expect(consumed.consumed).to.be.a('number');
    expect(consumed.isValid).to.be.false;
    await provider.AuthorizationCode.revokeByGrantId('grant');
    expect(await provider.AuthorizationCode.find(value)).to.be.undefined;
  });

  for (const name of grantBound.filter((value) => value !== 'PreAuthorizedCode')) {
    it(`${name} checks the session principal and grant and honours the explicit bypass`, async () => {
      const Model = provider[name];
      const value = await new Model({
        accountId: 'account', clientId: 'client', grantId: 'grant',
        sessionUid: 'session', expiresWithSession: true,
      }).save();
      const findSession = sinon.stub(provider.Session, 'findByUid').resolves(undefined);
      expect(await Model.find(value)).to.be.undefined;
      sinon.assert.calledOnceWithExactly(findSession, 'session');

      const sessionModel = new provider.Session({ accountId: 'account' });
      sessionModel.grantIdFor('client', 'grant');
      findSession.resolves(sessionModel);
      expect(await Model.find(value)).to.be.instanceOf(Model);
      sessionModel.accountId = 'other-account';
      expect(await Model.find(value)).to.be.undefined;
      sessionModel.accountId = 'account';
      sessionModel.grantIdFor('client', 'other-grant');
      expect(await Model.find(value)).to.be.undefined;

      findSession.resetHistory();
      expect(await Model.find(value, { ignoreSessionBinding: true })).to.be.instanceOf(Model);
      sinon.assert.notCalled(findSession);
      expect(await Model.find(value, { ignoreSessionBinding: 1 })).to.be.undefined;
      sinon.assert.calledOnce(findSession);
    });
  }

  for (const name of ['AccessToken', 'ClientCredentials']) {
    it(`${name} retains explicit and previously resolved token formats`, async () => {
      const Model = provider[name];
      const fresh = new Model({ expiresIn: 60 });
      await assert.rejects(fresh.getValueAndPayload(), { message: 'invalid format resolved' });
      fresh.format = 'opaque';
      expect((await fresh.getValueAndPayload()).payload).to.have.property('kind', name);
      for (const format of ['unsupported', 'dynamic']) {
        fresh.format = format;
        await assert.rejects(fresh.getValueAndPayload(), { message: 'invalid format resolved' });
        fresh.resourceServer = { audience: 'urn:resource', accessTokenFormat: format };
        expect(() => fresh.generateTokenId()).to.throw('invalid format resolved');
      }

      const issued = new Model({ expiresIn: 60 });
      issued.jti = issued.generateTokenId();
      issued.resourceServer = { audience: 'urn:resource', accessTokenFormat: 'jwt' };
      const value = await issued.save();
      expect(await issued.save()).to.equal(value);
      expect(issued.format).to.equal('opaque');

      class CustomToken extends Model {}
      const custom = new CustomToken({ jti: 'custom-id', expiresIn: 60 });
      custom.format = 'opaque';
      expect((await custom.getValueAndPayload()).value).to.equal('custom-id');
    });
  }
});
