import { generateKeyPair, exportJWK } from 'jose';

function exportJwk({ privateKey }) {
  return exportJWK(privateKey);
}

export default await Promise.all([
  generateKeyPair('RS256', { extractable: true }).then(exportJwk),
  generateKeyPair('ES256', { extractable: true }).then(exportJwk),
  generateKeyPair('EdDSA', { extractable: true }).then(exportJwk),
]);

export function stripPrivateJWKFields(key) {
  const publicKey = structuredClone(key);
  for (const k of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
    delete publicKey[k];
  }
  return publicKey;
}
