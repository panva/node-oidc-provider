import { generateKeyPairSync } from 'node:crypto';

import { createSandbox } from 'sinon';
import { expect } from 'chai';
import timekeeper from 'timekeeper';
import { SignJWT } from 'jose';

import bootstrap, { skipConsent } from '../test_helper.js';

const sinon = createSandbox();

function errorDetail(spy) {
  return spy.args[0][1].error_detail;
}

function attestation(instanceKeyPair) {
  return new SignJWT({
    cnf: {
      jwk: instanceKeyPair.publicKey.export({ format: 'jwk' }),
    },
  })
    .setProtectedHeader({
      typ: 'oauth-client-attestation+jwt',
      alg: 'Ed25519',
    })
    .setIssuer('https://attester.example.com')
    .setSubject('client')
    .setExpirationTime('2h')
    .sign(this.config.attestationKeyPair.privateKey);
}

function pop(instanceKeyPair) {
  const challenge = i(this.provider).AttestChallenges.nextChallenge();
  return new SignJWT({ challenge })
    .setProtectedHeader({
      typ: 'oauth-client-attestation-pop+jwt',
      alg: 'Ed25519',
    })
    .setIssuer('client')
    .setAudience(this.provider.issuer)
    .setJti(crypto.randomUUID())
    .sign(instanceKeyPair.privateKey);
}

describe('attest_jwt_client_auth bindings', () => {
  before(bootstrap(import.meta.url));

  afterEach(() => timekeeper.reset());
  afterEach(function () {
    this.provider.removeAllListeners();
  });
  afterEach(sinon.restore);

  beforeEach(function () { return this.login({ scope: 'openid email offline_access' }); });
  afterEach(function () { return this.logout(); });
  skipConsent();

  afterEach(function () {
    this.provider.removeAllListeners();
  });

  it('refresh token binding', async function () {
    const instanceKeyPair = generateKeyPairSync('ed25519');
    const { headers: { location } } = await this.agent.get('/auth')
      .query({
        client_id: 'client',
        scope: 'offline_access',
        prompt: 'consent',
        response_type: 'code',
      })
      .expect(303);

    const callback = new URL(location).searchParams;
    expect(callback.has('code')).to.be.true;
    const code = new URL(location).searchParams.get('code');

    const { body: { refresh_token } } = await this.agent.post('/token')
      .send({
        code,
        grant_type: 'authorization_code',
      })
      .type('form')
      .set('OAuth-Client-Attestation', await attestation.call(this, instanceKeyPair))
      .set('OAuth-Client-Attestation-PoP', await pop.call(this, instanceKeyPair))
      .expect(200);

    await this.agent.post('/token')
      .send({
        refresh_token,
        grant_type: 'refresh_token',
      })
      .type('form')
      .set('OAuth-Client-Attestation', await attestation.call(this, instanceKeyPair))
      .set('OAuth-Client-Attestation-PoP', await pop.call(this, instanceKeyPair))
      .expect(200);

    const spy = sinon.spy();
    this.provider.once('grant.error', spy);
    const instanceKeyPair2 = generateKeyPairSync('ed25519');
    await this.agent.post('/token')
      .send({
        refresh_token,
        grant_type: 'refresh_token',
      })
      .type('form')
      .set('OAuth-Client-Attestation', await attestation.call(this, instanceKeyPair2))
      .set('OAuth-Client-Attestation-PoP', await pop.call(this, instanceKeyPair2))
      .expect(400)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
        expect(errorDetail(spy)).to.equal('oauth-client-attestation instance public key mismatch');
      });

    {
      const { body: { active } } = await this.agent.post('/token/introspection')
        .send({
          token: refresh_token,
        })
        .type('form')
        .set('OAuth-Client-Attestation', await attestation.call(this, instanceKeyPair2))
        .set('OAuth-Client-Attestation-PoP', await pop.call(this, instanceKeyPair2))
        .expect(200);

      expect(active).to.be.false;

      await this.agent.post('/token/revocation')
        .send({
          token: refresh_token,
        })
        .type('form')
        .set('OAuth-Client-Attestation', await attestation.call(this, instanceKeyPair2))
        .set('OAuth-Client-Attestation-PoP', await pop.call(this, instanceKeyPair2))
        .expect(200);
    }

    {
      const { body: { active } } = await this.agent.post('/token/introspection')
        .send({
          token: refresh_token,
        })
        .type('form')
        .set('OAuth-Client-Attestation', await attestation.call(this, instanceKeyPair))
        .set('OAuth-Client-Attestation-PoP', await pop.call(this, instanceKeyPair))
        .expect(200);

      expect(active).to.be.true;

      await this.agent.post('/token/revocation')
        .send({
          token: refresh_token,
        })
        .type('form')
        .set('OAuth-Client-Attestation', await attestation.call(this, instanceKeyPair))
        .set('OAuth-Client-Attestation-PoP', await pop.call(this, instanceKeyPair))
        .expect(200);
    }

    {
      const { body: { active } } = await this.agent.post('/token/introspection')
        .send({
          token: refresh_token,
        })
        .type('form')
        .set('OAuth-Client-Attestation', await attestation.call(this, instanceKeyPair))
        .set('OAuth-Client-Attestation-PoP', await pop.call(this, instanceKeyPair))
        .expect(200);

      expect(active).to.be.false;
    }
  });

  it('PAR request_uri binding', async function () {
    const instanceKeyPair = generateKeyPairSync('ed25519');

    const { body: { request_uri } } = await this.agent.post('/request')
      .send({
        client_id: 'client',
        scope: 'offline_access',
        prompt: 'consent',
        response_type: 'code',
      })
      .type('form')
      .set('OAuth-Client-Attestation', await attestation.call(this, instanceKeyPair))
      .set('OAuth-Client-Attestation-PoP', await pop.call(this, instanceKeyPair))
      .expect(201);

    const { headers: { location } } = await this.agent.get('/auth')
      .query({
        client_id: 'client',
        request_uri,
      })
      .expect(303);

    const callback = new URL(location).searchParams;
    expect(callback.has('code')).to.be.true;
    const code = new URL(location).searchParams.get('code');

    const { body: { refresh_token } } = await this.agent.post('/token')
      .send({
        code,
        grant_type: 'authorization_code',
      })
      .type('form')
      .set('OAuth-Client-Attestation', await attestation.call(this, instanceKeyPair))
      .set('OAuth-Client-Attestation-PoP', await pop.call(this, instanceKeyPair))
      .expect(200);

    expect(this.TestAdapter.for('RefreshToken').syncFind(refresh_token)).to.have.property('attestationJkt').and.is.string;
  });

  it('PAR request_uri binding (instance mismatch)', async function () {
    const instanceKeyPair = generateKeyPairSync('ed25519');

    const { body: { request_uri } } = await this.agent.post('/request')
      .send({
        client_id: 'client',
        scope: 'offline_access',
        prompt: 'consent',
        response_type: 'code',
      })
      .type('form')
      .set('OAuth-Client-Attestation', await attestation.call(this, instanceKeyPair))
      .set('OAuth-Client-Attestation-PoP', await pop.call(this, instanceKeyPair))
      .expect(201);

    const { headers: { location } } = await this.agent.get('/auth')
      .query({
        client_id: 'client',
        request_uri,
      })
      .expect(303);

    const callback = new URL(location).searchParams;
    expect(callback.has('code')).to.be.true;
    const code = new URL(location).searchParams.get('code');

    let spy = sinon.spy();
    this.provider.once('grant.error', spy);
    const instanceKeyPair2 = generateKeyPairSync('ed25519');

    await this.agent.post('/token')
      .send({
        code,
        grant_type: 'authorization_code',
      })
      .type('form')
      .set('OAuth-Client-Attestation', await attestation.call(this, instanceKeyPair2))
      .set('OAuth-Client-Attestation-PoP', await pop.call(this, instanceKeyPair2))
      .expect(400)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
        expect(errorDetail(spy)).to.equal('oauth-client-attestation instance public key mismatch');
      });

    spy = sinon.spy();
    this.provider.once('grant.error', spy);
    await this.agent.post('/token')
      .send({
        code,
        grant_type: 'authorization_code',
      })
      .type('form')
      .set('OAuth-Client-Attestation', await attestation.call(this, instanceKeyPair))
      .set('OAuth-Client-Attestation-PoP', await pop.call(this, instanceKeyPair))
      .expect(200);
  });

  it('urn:ietf:params:oauth:grant-type:device_code', async function () {
    const instanceKeyPair = generateKeyPairSync('ed25519');
    const { body } = await this.agent.post('/device/auth')
      .send({
        client_id: 'client',
        scope: 'offline_access',
        prompt: 'consent',
      })
      .type('form')
      .set('OAuth-Client-Attestation', await attestation.call(this, instanceKeyPair))
      .set('OAuth-Client-Attestation-PoP', await pop.call(this, instanceKeyPair))
      .expect(200);

    const deviceCode = this.TestAdapter.for('DeviceCode').syncFind(body.device_code);

    expect(deviceCode).to.have.property('attestationJkt').and.is.string;

    deviceCode.grantId = this.getGrantId();
    deviceCode.accountId = this.getSub();
    deviceCode.scope = 'offline_access';

    const spy = sinon.spy();
    this.provider.once('grant.error', spy);
    const instanceKeyPair2 = generateKeyPairSync('ed25519');

    await this.agent.post('/token')
      .send({
        device_code: body.device_code,
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      })
      .type('form')
      .set('OAuth-Client-Attestation', await attestation.call(this, instanceKeyPair2))
      .set('OAuth-Client-Attestation-PoP', await pop.call(this, instanceKeyPair2))
      .expect(400)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
        expect(errorDetail(spy)).to.equal('oauth-client-attestation instance public key mismatch');
      });

    const { body: { refresh_token } } = await this.agent.post('/token')
      .send({
        device_code: body.device_code,
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      })
      .type('form')
      .set('OAuth-Client-Attestation', await attestation.call(this, instanceKeyPair))
      .set('OAuth-Client-Attestation-PoP', await pop.call(this, instanceKeyPair))
      .expect(200);

    expect(this.TestAdapter.for('RefreshToken').syncFind(refresh_token)).to.have.property('attestationJkt').and.is.string;
  });

  it('urn:openid:params:grant-type:ciba', async function () {
    const instanceKeyPair = generateKeyPairSync('ed25519');
    const { body } = await this.agent.post('/backchannel')
      .send({
        client_id: 'client',
        scope: 'openid offline_access',
        prompt: 'consent',
        login_hint: 'sub',
      })
      .type('form')
      .set('OAuth-Client-Attestation', await attestation.call(this, instanceKeyPair))
      .set('OAuth-Client-Attestation-PoP', await pop.call(this, instanceKeyPair))
      .expect(200);

    const authReq = this.TestAdapter.for('BackchannelAuthenticationRequest').syncFind(body.auth_req_id);

    expect(authReq).to.have.property('attestationJkt').and.is.string;

    authReq.grantId = this.getGrantId();
    authReq.accountId = this.getSub();
    authReq.scope = 'openid offline_access';

    const spy = sinon.spy();
    this.provider.once('grant.error', spy);
    const instanceKeyPair2 = generateKeyPairSync('ed25519');

    await this.agent.post('/token')
      .send({
        auth_req_id: body.auth_req_id,
        grant_type: 'urn:openid:params:grant-type:ciba',
      })
      .type('form')
      .set('OAuth-Client-Attestation', await attestation.call(this, instanceKeyPair2))
      .set('OAuth-Client-Attestation-PoP', await pop.call(this, instanceKeyPair2))
      .expect(400)
      .expect(() => {
        expect(spy.calledOnce).to.be.true;
        expect(errorDetail(spy)).to.equal('oauth-client-attestation instance public key mismatch');
      });

    const { body: { refresh_token } } = await this.agent.post('/token')
      .send({
        auth_req_id: body.auth_req_id,
        grant_type: 'urn:openid:params:grant-type:ciba',
      })
      .type('form')
      .set('OAuth-Client-Attestation', await attestation.call(this, instanceKeyPair))
      .set('OAuth-Client-Attestation-PoP', await pop.call(this, instanceKeyPair))
      .expect(200);

    expect(this.TestAdapter.for('RefreshToken').syncFind(refresh_token)).to.have.property('attestationJkt').and.is.string;
  });
});
