import { generateKeyPair } from 'jose';

function exportJwk({ privateKey }) {
  return privateKey.export({ format: 'jwk' });
}

export default await Promise.all([
  generateKeyPair('RS256').then(exportJwk),
  generateKeyPair('ES256').then(exportJwk),
  generateKeyPair('EdDSA', { crv: 'Ed25519' }).then(exportJwk),
]);

export function stripPrivateJWKFields(key) {
  const publicKey = structuredClone(key);
  for (const k of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
    delete publicKey[k];
  }
  return publicKey;
}
