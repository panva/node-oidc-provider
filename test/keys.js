import { generateKeyPair, exportJWK } from 'jose';

function exportJwk({ privateKey }) {
  return exportJWK(privateKey);
}

async function generate(alg) {
  const result = await generateKeyPair(alg, { extractable: true });
  return exportJwk(result);
}

const keys = [
  generate('RS256'),
  generate('ES256'),
  generate('EdDSA'),
  generate('Ed25519'),
];

for (const alg of ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87']) {
  if (SubtleCrypto.supports?.('generateKey', alg)) {
    keys.push(generate(alg));
  }
}

export default await Promise.all(keys);

export function stripPrivateJWKFields(key) {
  const publicKey = structuredClone(key);
  for (const k of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'priv']) {
    delete publicKey[k];
  }
  return publicKey;
}
