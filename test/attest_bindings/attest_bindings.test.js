import { describe, before, afterEach, beforeEach, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';

import { createSandbox } from 'sinon';
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
    .setSubject('client')
    .setIssuedAt()
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
    .setAudience(this.provider.issuer)
    .setJti(crypto.randomUUID())
    .setIssuedAt()
    .sign(instanceKeyPair.privateKey);
}

async function authHeaders(instanceKeyPair, path) {
  const headers = {
    'OAuth-Client-Attestation': await attestation.call(this, instanceKeyPair),
  };
  if (this.authMethod === 'attest_jwt_client_auth_dpop') {
    const nonce = i(this.provider).DPoPNonces.nextChallenge();
    headers.DPoP = await new SignJWT({ nonce, htm: 'POST', htu: new URL(this.suitePath(path), this.provider.issuer).href })
      .setProtectedHeader({
        typ: 'dpop+jwt',
        alg: 'Ed25519',
        jwk: instanceKeyPair.publicKey.export({ format: 'jwk' }),
      })
      .setJti(crypto.randomUUID())
      .setIssuedAt()
      .sign(instanceKeyPair.privateKey);
  } else {
    headers['OAuth-Client-Attestation-PoP'] = await pop.call(this, instanceKeyPair);
  }
  return headers;
}

for (const authMethod of ['attest_jwt_client_auth', 'attest_jwt_client_auth_dpop']) {
  describe(`${authMethod} bindings`, () => {
    const fixture = {};

    before(bootstrap(import.meta.url, fixture), { timeout: 3000 });
    before(async () => {
      fixture.authMethod = authMethod;
      const client = await fixture.provider.Client.find('client');
      client.tokenEndpointAuthMethod = authMethod;
    }, { timeout: 3000 });

    afterEach(() => timekeeper.reset(), { timeout: 3000 });
    afterEach(() => {
      fixture.provider.removeAllListeners();
    }, { timeout: 3000 });
    afterEach(() => sinon.restore(), { timeout: 3000 });

    beforeEach(() => fixture.login({ scope: 'openid email offline_access' }), { timeout: 3000 });
    afterEach(() => fixture.logout(), { timeout: 3000 });
    skipConsent(fixture);

    afterEach(() => {
      fixture.provider.removeAllListeners();
    }, { timeout: 3000 });

    it('refresh token binding', { timeout: 3000 }, async () => {
      const instanceKeyPair = generateKeyPairSync('ed25519');
      const { headers: { location } } = await fixture.agent.get('/auth')
        .query({
          client_id: 'client',
          scope: 'offline_access',
          prompt: 'consent',
          response_type: 'code',
        })
        .expect(303);

      const callback = new URL(location).searchParams;
      assert.equal(callback.has('code'), true);
      const code = new URL(location).searchParams.get('code');

      const { body: { refresh_token } } = await fixture.agent.post('/token')
        .send({
          code,
          grant_type: 'authorization_code',
        })
        .type('form')
        .set(await authHeaders.call(fixture, instanceKeyPair, '/token'))
        .expect(200);

      await fixture.agent.post('/token')
        .send({
          refresh_token,
          grant_type: 'refresh_token',
        })
        .type('form')
        .set(await authHeaders.call(fixture, instanceKeyPair, '/token'))
        .expect(200);

      const spy = sinon.spy();
      fixture.provider.once('grant.error', spy);
      const instanceKeyPair2 = generateKeyPairSync('ed25519');
      await fixture.agent.post('/token')
        .send({
          refresh_token,
          grant_type: 'refresh_token',
        })
        .type('form')
        .set(await authHeaders.call(fixture, instanceKeyPair2, '/token'))
        .expect(400)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'oauth-client-attestation instance public key mismatch');
        });

      {
        const { body: { active } } = await fixture.agent.post('/token/introspection')
          .send({
            token: refresh_token,
          })
          .type('form')
          .set(await authHeaders.call(fixture, instanceKeyPair2, '/token/introspection'))
          .expect(200);

        assert.equal(active, false);

        await fixture.agent.post('/token/revocation')
          .send({
            token: refresh_token,
          })
          .type('form')
          .set(await authHeaders.call(fixture, instanceKeyPair2, '/token/revocation'))
          .expect(200);
      }

      {
        const { body: { active } } = await fixture.agent.post('/token/introspection')
          .send({
            token: refresh_token,
          })
          .type('form')
          .set(await authHeaders.call(fixture, instanceKeyPair, '/token/introspection'))
          .expect(200);

        assert.equal(active, true);

        await fixture.agent.post('/token/revocation')
          .send({
            token: refresh_token,
          })
          .type('form')
          .set(await authHeaders.call(fixture, instanceKeyPair, '/token/revocation'))
          .expect(200);
      }

      {
        const { body: { active } } = await fixture.agent.post('/token/introspection')
          .send({
            token: refresh_token,
          })
          .type('form')
          .set(await authHeaders.call(fixture, instanceKeyPair, '/token/introspection'))
          .expect(200);

        assert.equal(active, false);
      }
    });

    it('PAR request_uri binding', { timeout: 3000 }, async () => {
      const instanceKeyPair = generateKeyPairSync('ed25519');

      const { body: { request_uri } } = await fixture.agent.post('/request')
        .send({
          client_id: 'client',
          scope: 'offline_access',
          prompt: 'consent',
          response_type: 'code',
        })
        .type('form')
        .set(await authHeaders.call(fixture, instanceKeyPair, '/request'))
        .expect(201);

      const { headers: { location } } = await fixture.agent.get('/auth')
        .query({
          client_id: 'client',
          request_uri,
        })
        .expect(303);

      const callback = new URL(location).searchParams;
      assert.equal(callback.has('code'), true);
      const code = new URL(location).searchParams.get('code');

      const { body: { refresh_token } } = await fixture.agent.post('/token')
        .send({
          code,
          grant_type: 'authorization_code',
        })
        .type('form')
        .set(await authHeaders.call(fixture, instanceKeyPair, '/token'))
        .expect(200);

      ((actual) => { assert.ok('attestationJkt' in Object(actual)); assert.equal(typeof actual.attestationJkt, 'string'); })(fixture.TestAdapter.for('RefreshToken').syncFind(refresh_token));
    });

    it('PAR request_uri binding (instance mismatch)', { timeout: 3000 }, async () => {
      const instanceKeyPair = generateKeyPairSync('ed25519');

      const { body: { request_uri } } = await fixture.agent.post('/request')
        .send({
          client_id: 'client',
          scope: 'offline_access',
          prompt: 'consent',
          response_type: 'code',
        })
        .type('form')
        .set(await authHeaders.call(fixture, instanceKeyPair, '/request'))
        .expect(201);

      const { headers: { location } } = await fixture.agent.get('/auth')
        .query({
          client_id: 'client',
          request_uri,
        })
        .expect(303);

      const callback = new URL(location).searchParams;
      assert.equal(callback.has('code'), true);
      const code = new URL(location).searchParams.get('code');

      let spy = sinon.spy();
      fixture.provider.once('grant.error', spy);
      const instanceKeyPair2 = generateKeyPairSync('ed25519');

      await fixture.agent.post('/token')
        .send({
          code,
          grant_type: 'authorization_code',
        })
        .type('form')
        .set(await authHeaders.call(fixture, instanceKeyPair2, '/token'))
        .expect(400)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'oauth-client-attestation instance public key mismatch');
        });

      spy = sinon.spy();
      fixture.provider.once('grant.error', spy);
      await fixture.agent.post('/token')
        .send({
          code,
          grant_type: 'authorization_code',
        })
        .type('form')
        .set(await authHeaders.call(fixture, instanceKeyPair, '/token'))
        .expect(200);
    });

    it('urn:ietf:params:oauth:grant-type:device_code', { timeout: 3000 }, async () => {
      const instanceKeyPair = generateKeyPairSync('ed25519');
      const { body } = await fixture.agent.post('/device/auth')
        .send({
          client_id: 'client',
          scope: 'offline_access',
          prompt: 'consent',
        })
        .type('form')
        .set(await authHeaders.call(fixture, instanceKeyPair, '/device/auth'))
        .expect(200);

      const deviceCode = fixture.TestAdapter.for('DeviceCode').syncFind(body.device_code);

      ((actual) => { assert.ok('attestationJkt' in Object(actual)); assert.equal(typeof actual.attestationJkt, 'string'); })(deviceCode);

      deviceCode.grantId = fixture.getGrantId();
      deviceCode.accountId = fixture.getSub();
      deviceCode.scope = 'offline_access';

      const spy = sinon.spy();
      fixture.provider.once('grant.error', spy);
      const instanceKeyPair2 = generateKeyPairSync('ed25519');

      await fixture.agent.post('/token')
        .send({
          device_code: body.device_code,
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        })
        .type('form')
        .set(await authHeaders.call(fixture, instanceKeyPair2, '/token'))
        .expect(400)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'oauth-client-attestation instance public key mismatch');
        });

      const { body: { refresh_token } } = await fixture.agent.post('/token')
        .send({
          device_code: body.device_code,
          grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        })
        .type('form')
        .set(await authHeaders.call(fixture, instanceKeyPair, '/token'))
        .expect(200);

      ((actual) => { assert.ok('attestationJkt' in Object(actual)); assert.equal(typeof actual.attestationJkt, 'string'); })(fixture.TestAdapter.for('RefreshToken').syncFind(refresh_token));
    });

    it('urn:openid:params:grant-type:ciba', { timeout: 3000 }, async () => {
      const instanceKeyPair = generateKeyPairSync('ed25519');
      const { body } = await fixture.agent.post('/backchannel')
        .send({
          client_id: 'client',
          scope: 'openid offline_access',
          prompt: 'consent',
          login_hint: 'sub',
        })
        .type('form')
        .set(await authHeaders.call(fixture, instanceKeyPair, '/backchannel'))
        .expect(200);

      const authReq = fixture.TestAdapter.for('BackchannelAuthenticationRequest').syncFind(body.auth_req_id);

      ((actual) => { assert.ok('attestationJkt' in Object(actual)); assert.equal(typeof actual.attestationJkt, 'string'); })(authReq);

      authReq.grantId = fixture.getGrantId();
      authReq.accountId = fixture.getSub();
      authReq.scope = 'openid offline_access';

      const spy = sinon.spy();
      fixture.provider.once('grant.error', spy);
      const instanceKeyPair2 = generateKeyPairSync('ed25519');

      await fixture.agent.post('/token')
        .send({
          auth_req_id: body.auth_req_id,
          grant_type: 'urn:openid:params:grant-type:ciba',
        })
        .type('form')
        .set(await authHeaders.call(fixture, instanceKeyPair2, '/token'))
        .expect(400)
        .expect(() => {
          assert.equal(spy.calledOnce, true);
          assert.equal(errorDetail(spy), 'oauth-client-attestation instance public key mismatch');
        });

      const { body: { refresh_token } } = await fixture.agent.post('/token')
        .send({
          auth_req_id: body.auth_req_id,
          grant_type: 'urn:openid:params:grant-type:ciba',
        })
        .type('form')
        .set(await authHeaders.call(fixture, instanceKeyPair, '/token'))
        .expect(200);

      ((actual) => { assert.ok('attestationJkt' in Object(actual)); assert.equal(typeof actual.attestationJkt, 'string'); })(fixture.TestAdapter.for('RefreshToken').syncFind(refresh_token));
    });
  });
}
