import { subtle } from 'node:crypto';

import { decodeProtectedHeader, errors } from 'jose';

import { get } from './hpke_algorithms.js';

const { JWEInvalid, JOSENotSupported } = errors;

export async function importKey(key, operation = 'encrypt', alg = key?.alg) {
  const entry = get(alg);
  if (!entry?.supported) throw new JOSENotSupported(`HPKE JWE algorithm (${alg}) is not supported by this runtime`);
  const { kty, algorithm } = entry;
  const type = operation === 'encrypt' ? 'public' : 'private';
  const usage = operation === 'encrypt' ? 'encapsulateBits' : 'decapsulateBits';

  if (!(key instanceof CryptoKey)) {
    if (key?.kty !== kty || key.alg !== alg
        || typeof key.pub !== 'string' || !key.pub
        || (key.use !== undefined && key.use !== 'enc')
        || (type === 'public' && key.priv !== undefined)) {
      throw new TypeError(`${alg} requires a ${type} ${kty} encryption key`);
    }
    key = await subtle.importKey('jwk', { ...key, alg: algorithm }, algorithm, false, [usage]);
  }

  if (key.type !== type || key.algorithm.name !== algorithm || !key.usages.includes(usage)) {
    throw new TypeError(`${alg} requires a ${type} ${algorithm} key with ${usage} usage`);
  }
  return key;
}

function validateHeader(header) {
  const entry = get(header.alg);
  if (!entry?.integrated) throw new JOSENotSupported(`unsupported HPKE JWE algorithm (${header.alg})`);
  if (header.enc !== undefined || header.ek !== undefined) {
    throw new JWEInvalid('Integrated Encryption requires absent enc and ek Header Parameters');
  }
  if (header.crit !== undefined || header.psk_id !== undefined || header.zip !== undefined) {
    throw new JOSENotSupported('HPKE JWE critical extensions, Pre-Shared Key mode, and compression are not supported');
  }
  return entry;
}

export async function encrypt(cleartext, key, protectedHeader) {
  const { suite } = validateHeader(protectedHeader);
  const recipient = await importKey(key, 'encrypt', protectedHeader.alg);
  const encoded = Buffer.from(JSON.stringify(protectedHeader)).toString('base64url');
  const { encapsulatedSecret, ciphertext } = await suite.Seal(recipient, cleartext, {
    aad: Buffer.from(encoded),
  });
  return [encoded, Buffer.from(encapsulatedSecret).toString('base64url'), '', Buffer.from(ciphertext).toString('base64url'), ''].join('.');
}

export async function decrypt(jwe, key) {
  const parts = jwe.split('.');
  if (parts.length !== 5 || parts[2] !== '' || parts[4] !== ''
      || ![parts[0], parts[1], parts[3]].every((part) => /^[A-Za-z0-9_-]+$/.test(part))) {
    throw new JWEInvalid('Invalid HPKE JWE Compact Serialization');
  }
  const protectedHeader = decodeProtectedHeader(jwe);
  const { suite } = validateHeader(protectedHeader);
  const recipient = await importKey(key, 'decrypt', protectedHeader.alg);
  const plaintext = await suite.Open(
    recipient,
    Buffer.from(parts[1], 'base64url'),
    Buffer.from(parts[3], 'base64url'),
    { aad: Buffer.from(parts[0]) },
  );
  return { plaintext, protectedHeader };
}
