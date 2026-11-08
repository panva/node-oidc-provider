import { before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

import Provider from '../../lib/index.js';
import { JWA } from '../../lib/consts/index.js';
import addClient from '../../lib/helpers/add_client.js';
import KeyStore from '../../lib/helpers/keystore.js';
import { algorithms, get, isHPKE, isIntegrated, supportedAlgorithms } from '../../lib/helpers/hpke_algorithms.js';
import instance from '../../lib/helpers/weak_cache.js';
import getConfig from '../default.config.js';
import keys from '../keys.js';

const cases = [
  { alg: 'HPKE-9', algorithm: 'MLKEM768-X25519' },
  { alg: 'HPKE-12', algorithm: 'ML-KEM-768' },
  { alg: 'HPKE-13', algorithm: 'ML-KEM-1024' },
];
const contexts = [
  'idToken', 'userinfo', 'introspection', 'authorization', 'requestObject', 'credential',
];
const attributes = [
  'id_token_encrypted_response_alg',
  'userinfo_encrypted_response_alg',
  'introspection_encrypted_response_alg',
  'authorization_encrypted_response_alg',
  'request_object_encryption_alg',
];
const unsupportedAlgorithms = [
  'HPKE-0', 'HPKE-0-KE', 'HPKE-1', 'HPKE-1-KE', 'HPKE-2', 'HPKE-2-KE',
  'HPKE-3', 'HPKE-3-KE', 'HPKE-4', 'HPKE-5', 'HPKE-5-KE', 'HPKE-6',
  'HPKE-7', 'HPKE-7-KE', 'HPKE-8', 'HPKE-8-KE', 'HPKE-9-KE',
  'HPKE-10', 'HPKE-10-KE', 'HPKE-12-KE', 'HPKE-13-KE',
  'HPKE-4-KE', 'HPKE-6-KE', 'HPKE-11', 'HPKE-11-KE', 'HPKE-99',
];

describe('HPKE key selection', () => {
  it('registers the PQC Integrated Encryption algorithms', () => {
    assert.deepEqual(algorithms, cases.map(({ alg }) => alg));
    for (const { alg } of cases) {
      assert.equal(isHPKE(alg), true);
      assert.equal(isIntegrated(alg), true);
    }
  });

  for (const { alg } of cases) {
    it(`${alg} requires AKP keys with an explicit matching algorithm`, () => {
      const key = { kty: 'AKP', alg, pub: 'public-key' };
      const store = new KeyStore([
        { ...key, kty: 'OKP', crv: 'X25519' },
        { ...key, alg: undefined },
        { ...key, alg: 'ML-DSA-44' },
        ...cases.filter((entry) => entry.alg !== alg).map((entry) => ({ ...key, alg: entry.alg })),
        { ...key, use: 'sig' },
        key,
      ]);
      assert.deepEqual(store.selectForEncrypt({ alg }), [key]);
      assert.deepEqual(store.selectForDecrypt({ alg }), [key]);
    });

    it(`${alg} honors encapsulateBits and decapsulateBits key operations`, () => {
      const encrypt = { kty: 'AKP', alg, key_ops: ['encapsulateBits'] };
      const decrypt = { kty: 'AKP', alg, key_ops: ['decapsulateBits'] };
      const store = new KeyStore([
        encrypt,
        decrypt,
        { kty: 'AKP', alg, key_ops: [] },
        { kty: 'AKP', alg, key_ops: ['deriveBits'] },
      ]);
      assert.deepEqual(store.selectForEncrypt({ alg }), [encrypt]);
      assert.deepEqual(store.selectForDecrypt({ alg }), [decrypt]);
    });
  }

  it('advertises support only when the required native algorithms are available', () => {
    const expected = [];
    for (const { alg, algorithm } of cases) {
      const nativeSupported = globalThis.SubtleCrypto?.supports?.('generateKey', algorithm) === true
        && globalThis.SubtleCrypto.supports('digest', { name: 'cSHAKE256', outputLength: 864 }) === true;
      assert.equal(get(alg).supported, nativeSupported);
      if (nativeSupported) expected.push(alg);
    }
    assert.deepEqual(supportedAlgorithms, expected);
    for (const context of contexts) {
      assert.deepEqual(JWA[`${context}EncryptionAlgValues`].filter(isHPKE), supportedAlgorithms);
    }
  });

  it('rejects other HPKE identifiers', () => {
    const store = new KeyStore();
    for (const unsupported of unsupportedAlgorithms) {
      assert.equal(get(unsupported), undefined);
      assert.equal(isHPKE(unsupported), false);
      assert.equal(isIntegrated(unsupported), false);
      assert.throws(() => store.selectForEncrypt({ alg: unsupported }), /unsupported JWE key management algorithm/);
    }
  });

  it('rejects other HPKE algorithms in enabledJWA configuration', () => {
    for (const context of contexts) {
      const property = `${context}EncryptionAlgValues`;
      for (const unsupported of unsupportedAlgorithms) {
        assert.throws(() => new Provider('https://issuer.example.com', {
          enabledJWA: { [property]: [unsupported] },
        }), /unsupported enabledJWA\./);
      }
    }
  });
});

describe('HPKE feature flag', () => {
  it('disables HPKE by default while keeping other encryption algorithms available', () => {
    const config = getConfig();
    for (const feature of [
      'encryption', 'requestObjects', 'jwtUserinfo', 'introspection', 'jwtIntrospection', 'jwtResponseModes',
    ]) {
      config.features[feature] = { enabled: true };
    }
    const provider = new Provider('https://issuer.example.com', config);
    const { configuration } = instance(provider);
    assert.equal(configuration.features.hpke.enabled, false);
    for (const context of contexts) {
      assert.deepEqual(configuration.enabledJWA[`${context}EncryptionAlgValues`].filter(isHPKE), []);
    }
    for (const context of contexts.filter((value) => value !== 'credential')) {
      assert.deepEqual(configuration[`${context}EncryptionAlgValues`].filter(isHPKE), []);
    }
    assert.ok(configuration.idTokenEncryptionAlgValues.includes('RSA-OAEP-256'));
  });

  it('rejects a stale draft acknowledgement', () => {
    assert.throws(() => new Provider('https://issuer.example.com', {
      features: {
        encryption: { enabled: true },
        hpke: { enabled: true, ack: 'draft-01' },
      },
    }), /An unacknowledged version of an experimental feature/);
  });

  it('requires the encryption feature', () => {
    assert.throws(() => new Provider('https://issuer.example.com', {
      features: { hpke: { enabled: true, ack: 'draft-02' } },
    }), /features\.hpke requires features\.encryption/);
  });
});

for (const { alg } of cases) {
  describe(`${alg} configuration`, { skip: !get(alg).supported }, () => {
    let provider;
    let publicJwk;

    before(async () => {
      const pair = await get(alg).suite.GenerateKeyPair(true);
      const privateJwk = await webcrypto.subtle.exportKey('jwk', pair.privateKey);
      publicJwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
      for (const jwk of [privateJwk, publicJwk]) {
        Object.assign(jwk, { alg, kid: alg, use: 'enc' });
        delete jwk.key_ops;
        delete jwk.ext;
      }
      const config = getConfig();
      config.features.hpke = { enabled: true, ack: 'draft-02' };
      config.jwks = { keys: [...keys, privateJwk] };
      for (const feature of [
        'encryption', 'requestObjects', 'jwtUserinfo', 'introspection', 'jwtIntrospection', 'jwtResponseModes',
      ]) {
        config.features[feature] = { enabled: true };
      }
      provider = new Provider('https://issuer.example.com', config);
    });

    it('publishes a public encryption key and enables encrypted Request Objects', () => {
      const { configuration, jwks } = instance(provider);
      assert.ok(configuration.requestObjectEncryptionAlgValues.includes(alg));
      const jwk = jwks.keys.find((key) => key.kid === alg);
      assert.deepEqual(JSON.parse(JSON.stringify(jwk)), publicJwk);
    });

    function metadata(attribute, extra = {}) {
      return {
        client_id: attribute,
        client_secret: 'secret',
        redirect_uris: ['https://client.example.com/cb'],
        id_token_signed_response_alg: 'RS256',
        userinfo_signed_response_alg: 'RS256',
        introspection_signed_response_alg: 'RS256',
        authorization_signed_response_alg: 'RS256',
        jwks: { keys: [publicJwk] },
        [attribute]: alg,
        ...extra,
      };
    }

    for (const attribute of attributes) {
      const enc = attribute.replace(/alg$/, 'enc');

      it(`does not default ${enc} for Integrated Encryption`, async () => {
        const client = await addClient(provider, metadata(attribute));
        assert.equal(client.metadata()[attribute], alg);
        assert.equal(client.metadata()[enc], undefined);
        assert.deepEqual(client.asymmetricKeyStore.selectForEncrypt({ alg }), [publicJwk]);
      });

      it(`rejects explicit ${enc} for Integrated Encryption`, async () => {
        await assert.rejects(addClient(provider, metadata(attribute, { [enc]: 'A128GCM' })), {
          error_description: `${enc} must not be provided when ${attribute} is ${alg}`,
        });
      });

      it(`rejects other HPKE algorithms in ${attribute}`, async () => {
        for (const unsupported of unsupportedAlgorithms) {
          await assert.rejects(addClient(provider, metadata(attribute, { [attribute]: unsupported })));
        }
      });

      if (attribute !== 'request_object_encryption_alg') {
        it(`requires client keys for ${attribute}`, async () => {
          await assert.rejects(addClient(provider, metadata(attribute, { jwks: undefined })), {
            error_description: 'jwks or jwks_uri is mandatory for this client',
          });
        });
      }
    }
  });
}
