import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';

import Provider from '../../lib/index.js';
import getConfig from '../default.config.js';
import encryption from '../jwks/jwks-enc.config.js';

const rsa = encryption.config.jwks.keys.find((key) => key.alg === 'RSA-OAEP');
const ecdh = encryption.config.jwks.keys.find((key) => key.alg === 'ECDH-ES');

function configuration(key) {
  const config = getConfig();
  config.features.encryption = { enabled: true };
  config.jwks = { keys: [structuredClone(key)] };
  return config;
}

function rejectsKeyOperations(key) {
  assert.throws(() => new Provider('https://issuer.example.com', configuration(key)), {
    message: 'jwks.keys[0].key_ops is not supported',
  });
}

describe('provider key operations configuration', () => {
  it('rejects key_ops without interpreting its value', () => {
    for (const key_ops of [['decrypt'], [], ['sign', 'sign'], ['unknown'], null, 'decrypt']) {
      rejectsKeyOperations({ ...rsa, key_ops });
    }
  });

  for (const [operation, source, algorithm] of [
    ['sign', rsa, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }],
    ['decrypt', rsa, { name: 'RSA-OAEP', hash: 'SHA-1' }],
    ['deriveBits', ecdh, { name: 'ECDH', namedCurve: 'P-256' }],
  ]) {
    it(`rejects key_ops from a native WebCrypto ${operation} export`, async () => {
      const { alg, use, key_ops, ...material } = source;
      const key = await webcrypto.subtle.importKey('jwk', material, algorithm, true, [operation]);
      const jwk = await webcrypto.subtle.exportKey('jwk', key);
      assert.deepEqual(jwk.key_ops, [operation]);
      rejectsKeyOperations(jwk);
    });
  }

  it('accepts provider keys without key_ops', () => {
    assert.doesNotThrow(() => new Provider('https://issuer.example.com', configuration(rsa)));
  });
});
