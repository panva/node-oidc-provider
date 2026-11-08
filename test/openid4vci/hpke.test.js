import { afterEach, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { createSandbox } from 'sinon';

import bootstrap from '../test_helper.js';
import * as JWT from '../../lib/helpers/jwt.js';
import KeyStore from '../../lib/helpers/keystore.js';
import { get } from '../../lib/helpers/hpke_algorithms.js';
import instance from '../../lib/helpers/weak_cache.js';
import { cases, credentialResponse } from './hpke.config.js';

const sinon = createSandbox();
const credentialRequest = { credential_configuration_id: 'example' };

describe('OpenID4VCI HPKE Integrated Encryption', { skip: !cases.length }, () => {
  const fixture = {};
  before(bootstrap(import.meta.url, fixture, { config: 'hpke' }), { timeout: 3000 });
  afterEach(() => sinon.restore());

  function feature() {
    return instance(fixture.provider).features.openid4vci;
  }

  async function accessToken() {
    const client = await fixture.provider.Client.find('wallet');
    const resource = `${fixture.provider.issuer}${fixture.suitePath('/credential')}`;
    const grant = new fixture.provider.Grant({ accountId: 'account', clientId: client.clientId });
    grant.addResourceScope(resource, 'credential_scope');
    const token = new fixture.provider.AccessToken({
      accountId: 'account',
      aud: resource,
      client,
      grantId: await grant.save(),
      scope: 'credential_scope',
    });
    return token.save();
  }

  async function post(body, { alg, issuer }, mutate) {
    let encrypted = await JWT.encrypt(JSON.stringify(body), issuer.publicJwk, { alg, fields: { kid: issuer.publicJwk.kid } });
    if (mutate) encrypted = mutate(encrypted);
    return fixture.agent.post('/credential')
      .set('Authorization', `Bearer ${await accessToken()}`)
      .type('application/jwt')
      .send(encrypted);
  }

  it('publishes the HPKE issuer keys and response algorithms', async () => {
    const { body } = await fixture.agent.get('/.well-known/openid-credential-issuer').expect(200);
    assert.deepEqual(body.credential_request_encryption.jwks.keys, cases.map(({ issuer }) => issuer.publicJwk));
    assert.deepEqual(body.credential_response_encryption.alg_values_supported, cases.map(({ alg }) => alg));
    assert.equal(body.credential_request_encryption.encryption_required, false);
    assert.equal(body.credential_response_encryption.encryption_required, false);
    assert.ok(body.credential_request_encryption.jwks.keys.every((key) => !Object.hasOwn(key, 'priv')));
  });

  for (const testCase of cases) {
    const { alg, recipient } = testCase;

    describe(`${alg} Integrated Encryption`, () => {
      it('decrypts a credential request', async () => {
        const spy = sinon.spy(feature(), 'issueCredential');
        const response = await post(credentialRequest, testCase);
        assert.equal(response.status, 200);
        assert.deepEqual(response.body, credentialResponse);
        assert.equal(spy.callCount, 1);
        assert.deepEqual(spy.firstCall.args[1].body, credentialRequest);
      });

      for (const keyOps of [undefined, ['encapsulateBits']]) {
        it(`encrypts the complete response with ${keyOps ? 'explicit' : 'omitted'} recipient key operations`, async () => {
          const response = await post({
            ...credentialRequest,
            credential_response_encryption: { jwk: { ...recipient.publicJwk, key_ops: keyOps } },
          }, testCase);
          assert.equal(response.status, 200);
          assert.match(response.headers['content-type'], /^application\/jwt/);
          assert.match(response.headers['cache-control'], /no-store/);
          assert.deepEqual(JWT.header(response.text), { alg, kid: recipient.publicJwk.kid });
          const parts = response.text.split('.');
          assert.equal(Buffer.from(parts[1], 'base64url').length, get(alg).suite.KEM.Nenc);
          assert.equal(parts[2], '');
          assert.equal(parts[4], '');
          const plaintext = await JWT.decrypt(response.text, new KeyStore([recipient.privateJwk]));
          assert.deepEqual(JSON.parse(plaintext), credentialResponse);
        });
      }

      for (const [name, parameters] of [
        ['enc', () => ({ jwk: recipient.publicJwk, enc: 'A256GCM' })],
        ['a private key', () => ({ jwk: recipient.privateJwk })],
        ['the wrong key type', () => ({ jwk: { ...recipient.publicJwk, kty: 'OKP' } })],
        ['a signing key', () => ({ jwk: { ...recipient.publicJwk, use: 'sig' } })],
        ['incompatible key operations', () => ({ jwk: { ...recipient.publicJwk, key_ops: ['deriveBits'] } })],
        ['empty key operations', () => ({ jwk: { ...recipient.publicJwk, key_ops: [] } })],
        ['invalid public key material', () => ({ jwk: { ...recipient.publicJwk, pub: 'invalid' } })],
        ['a missing algorithm', () => ({ jwk: { ...recipient.publicJwk, alg: undefined } })],
        ['unsupported HPKE-1', () => ({ jwk: { ...recipient.publicJwk, alg: 'HPKE-1' } })],
        ['unsupported HPKE-9-KE', () => ({ jwk: { ...recipient.publicJwk, alg: 'HPKE-9-KE' } })],
      ]) {
        it(`rejects response encryption with ${name} before issuance`, async () => {
          const spy = sinon.spy(feature(), 'issueCredential');
          const response = await post({ ...credentialRequest, credential_response_encryption: parameters() }, testCase);
          assert.equal(response.status, 400);
          assert.equal(response.body.error, 'invalid_encryption_parameters');
          assert.equal(spy.callCount, 0);
        });
      }

      for (const [name, header] of [
        ['present enc', { enc: 'A256GCM' }],
        ['an unknown key ID', { kid: 'unknown' }],
        ['unsupported HPKE-1', { alg: 'HPKE-1' }],
        ['unsupported HPKE-9-KE', { alg: 'HPKE-9-KE' }],
      ]) {
        it(`rejects credential requests carrying ${name} before issuance`, async () => {
          const spy = sinon.spy(feature(), 'issueCredential');
          const response = await post(credentialRequest, testCase, (encrypted) => {
            const parts = encrypted.split('.');
            parts[0] = Buffer.from(JSON.stringify({ ...JWT.header(encrypted), ...header })).toString('base64url');
            return parts.join('.');
          });
          assert.equal(response.status, 400);
          assert.equal(response.body.error, 'invalid_credential_request');
          assert.equal(spy.callCount, 0);
        });
      }
    });
  }
});
