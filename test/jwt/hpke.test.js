import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import assert from 'node:assert/strict';
import { describe, it, before } from 'node:test';

import { decodeProtectedHeader } from 'jose';

import * as HPKE from '../../lib/helpers/hpke.js';
import * as algorithms from '../../lib/helpers/hpke_algorithms.js';
import * as JWT from '../../lib/helpers/jwt.js';
import KeyStore from '../../lib/helpers/keystore.js';

// draft-ietf-jose-hpke-pq-pqt-02, Appendix A, HPKE-9.
// https://www.ietf.org/archive/id/draft-ietf-jose-hpke-pq-pqt-02.html#appendix-A
const [vector] = JSON.parse(await readFile(new URL('./hpke-vectors.json', import.meta.url)));
const publicJwk = { ...vector.jwk };
delete publicJwk.priv;
const cleartext = Buffer.from('HPKE encrypted payload: ś∂źć√');
const cases = [
  { alg: 'HPKE-9', encapsulatedLength: 1120 },
  { alg: 'HPKE-12', encapsulatedLength: 1088 },
  { alg: 'HPKE-13', encapsulatedLength: 1568 },
];

function replaceSegment(jwe, index, value) {
  const segments = jwe.split('.');
  segments[index] = value;
  return segments.join('.');
}

function replaceHeader(jwe, values) {
  return replaceSegment(jwe, 0, Buffer.from(JSON.stringify({
    ...decodeProtectedHeader(jwe), ...values,
  })).toString('base64url'));
}

function tamperSegment(jwe, index) {
  const segment = Buffer.from(jwe.split('.')[index], 'base64url');
  segment[0] ^= 1;
  return replaceSegment(jwe, index, segment.toString('base64url'));
}

describe('JOSE HPKE algorithm support', () => {
  it('enables the PQC Integrated Encryption algorithms', () => {
    assert.deepEqual(algorithms.algorithms, cases.map(({ alg }) => alg));
    assert.deepEqual(algorithms.supportedAlgorithms, cases.filter(({ alg }) => algorithms.get(alg).supported).map(({ alg }) => alg));
    for (const { alg } of cases) {
      assert.equal(algorithms.isHPKE(alg), true);
      assert.equal(algorithms.isIntegrated(alg), true);
    }
  });

  for (const alg of [
    'HPKE-0', 'HPKE-0-KE', 'HPKE-1', 'HPKE-1-KE', 'HPKE-2', 'HPKE-2-KE',
    'HPKE-3', 'HPKE-3-KE', 'HPKE-4', 'HPKE-4-KE', 'HPKE-5', 'HPKE-5-KE',
    'HPKE-6', 'HPKE-6-KE', 'HPKE-7', 'HPKE-7-KE', 'HPKE-8', 'HPKE-8-KE',
    'HPKE-9-KE', 'HPKE-10', 'HPKE-10-KE', 'HPKE-11', 'HPKE-11-KE',
    'HPKE-12-KE', 'HPKE-13-KE',
  ]) {
    it(`rejects the unsupported algorithm ${alg}`, async () => {
      assert.equal(algorithms.get(alg), undefined);
      assert.equal(algorithms.isHPKE(alg), false);
      await assert.rejects(HPKE.encrypt(cleartext, publicJwk, { alg }));
      await assert.rejects(HPKE.decrypt(replaceHeader(vector.compact, { alg }), vector.jwk));
    });
  }
});

for (const { alg, encapsulatedLength } of cases) {
  describe(alg, { skip: !algorithms.get(alg)?.supported }, () => {
    let keypair;
    let jwe;
    let privateJwk;
    let publicJwk;

    before(async () => {
      keypair = await algorithms.get(alg).suite.GenerateKeyPair(true);
      if (alg === 'HPKE-9') {
        privateJwk = vector.jwk;
      } else {
        const recipient = await algorithms.get(alg).suite.GenerateKeyPair(true);
        privateJwk = { ...await crypto.subtle.exportKey('jwk', recipient.privateKey), alg, kid: alg };
      }
      publicJwk = { ...privateJwk };
      delete publicJwk.priv;
      publicJwk.key_ops = ['encapsulateBits'];
      jwe = await HPKE.encrypt(cleartext, publicJwk, { alg });
    });

    if (alg === 'HPKE-9') {
      it('decrypts the published draft vector', async () => {
        const { plaintext, protectedHeader } = await HPKE.decrypt(vector.compact, privateJwk);
        assert.deepEqual(protectedHeader, { alg, kid: privateJwk.kid });
        assert.equal(
          createHash('sha256').update(plaintext).digest('hex'),
          'f5c3e318a8c09ba078afdf853fcbb871e91844fa444ee8764bacf5dece5bc8b4',
        );
      });
    }

    it('uses the JWE Compact Serialization for Integrated Encryption', async () => {
      const header = { alg, kid: publicJwk.kid, cty: 'JWT' };
      const encrypted = await HPKE.encrypt(cleartext, publicJwk, header);
      const segments = encrypted.split('.');
      assert.equal(segments.length, 5);
      assert.deepEqual(decodeProtectedHeader(encrypted), header);
      assert.equal(Buffer.from(segments[1], 'base64url').length, encapsulatedLength);
      assert.equal(segments[2], '');
      assert.equal(Buffer.from(segments[3], 'base64url').length, cleartext.length + 16);
      assert.equal(segments[4], '');
      assert.deepEqual(Buffer.from((await HPKE.decrypt(encrypted, privateJwk)).plaintext), cleartext);
    });

    it('encrypts with a fresh encapsulation for each message', async () => {
      const first = await HPKE.encrypt(cleartext, publicJwk, { alg });
      const second = await HPKE.encrypt(cleartext, publicJwk, { alg });
      assert.notEqual(first.split('.')[1], second.split('.')[1]);
      assert.notEqual(first.split('.')[3], second.split('.')[3]);
    });

    it('supports an empty plaintext', async () => {
      const encrypted = await HPKE.encrypt(Buffer.alloc(0), publicJwk, { alg });
      assert.equal((await HPKE.decrypt(encrypted, privateJwk)).plaintext.length, 0);
    });

    it('accepts native CryptoKeys', async () => {
      const encrypted = await HPKE.encrypt(cleartext, keypair.publicKey, { alg });
      const { plaintext } = await HPKE.decrypt(encrypted, keypair.privateKey);
      assert.deepEqual(Buffer.from(plaintext), cleartext);
    });

    it('preserves imported native keys', async () => {
      assert.equal(await HPKE.importKey(keypair.publicKey, 'encrypt', alg), keypair.publicKey);
      assert.equal(await HPKE.importKey(keypair.privateKey, 'decrypt', alg), keypair.privateKey);
    });

    it('supports JWK key operations for encapsulation and decapsulation', async () => {
      const encrypted = await HPKE.encrypt(cleartext, {
        ...publicJwk, key_ops: ['encapsulateBits'],
      }, { alg });
      const { plaintext } = await HPKE.decrypt(encrypted, {
        ...privateJwk, key_ops: ['decapsulateBits'],
      });
      assert.deepEqual(Buffer.from(plaintext), cleartext);
    });

    it('dispatches JWT encryption and decryption through the keystore', async () => {
      const encrypted = await JWT.encrypt(cleartext.toString(), publicJwk, {
        alg, kid: publicJwk.kid,
      });
      assert.deepEqual(await JWT.decrypt(encrypted, new KeyStore([privateJwk])), cleartext);
    });

    it('tries another matching key after a failed decryption', async () => {
      const incorrect = await crypto.subtle.exportKey('jwk', keypair.privateKey);
      const keystore = new KeyStore([
        { ...incorrect, alg },
        privateJwk,
      ]);
      assert.deepEqual(await JWT.decrypt(jwe, keystore), cleartext);
    });

    for (const [label, header] of [
      ['a content encryption algorithm', { enc: 'A256GCM' }],
      ['an empty content encryption algorithm', { enc: '' }],
      ['an ek Header Parameter', { ek: 'AA' }],
      ['a pre-shared key identifier', { psk_id: 'AA' }],
      ['compression', { zip: 'DEF' }],
      ['an unsupported critical header', { crit: ['unknown'], unknown: true }],
    ]) {
      it(`rejects ${label}`, async () => {
        await assert.rejects(HPKE.encrypt(cleartext, publicJwk, { alg, ...header }));
        await assert.rejects(HPKE.decrypt(replaceHeader(jwe, header), privateJwk));
      });
    }

    for (const [label, change] of [
      ['fewer compact segments', (value) => value.slice(0, -1)],
      ['extra compact segments', (value) => `${value}.`],
      ['a missing encapsulated secret', (value) => replaceSegment(value, 1, '')],
      ['a short encapsulated secret', (value) => replaceSegment(value, 1, 'AA')],
      ['a nonempty initialization vector', (value) => replaceSegment(value, 2, 'AA')],
      ['a nonempty authentication tag', (value) => replaceSegment(value, 4, 'AA')],
      ['a ciphertext shorter than the authentication tag', (value) => replaceSegment(value, 3, 'AA')],
      ['a padded base64url segment', (value) => replaceSegment(value, 1, `${value.split('.')[1]}=`)],
      ['whitespace in a base64url segment', (value) => replaceSegment(value, 1, `${value.split('.')[1]}\n`)],
      ['an invalid base64url segment', (value) => replaceSegment(value, 1, '*')],
      ['an unsupported algorithm', (value) => replaceHeader(value, { alg: 'HPKE-11' })],
      ['a changed protected header', (value) => replaceHeader(value, { kid: 'changed' })],
      ['a changed encapsulated secret', (value) => tamperSegment(value, 1)],
      ['a changed ciphertext', (value) => tamperSegment(value, 3)],
    ]) {
      it(`rejects ${label}`, async () => {
        await assert.rejects(HPKE.decrypt(change(jwe), privateJwk));
      });
    }

    it('rejects a different recipient key', async () => {
      await assert.rejects(HPKE.decrypt(jwe, keypair.privateKey));
    });

    for (const [label, key] of [
      ['a missing algorithm', () => ({ ...publicJwk, alg: undefined })],
      ['a different algorithm', () => ({ ...publicJwk, alg: 'HPKE-8' })],
      ['a different key type', () => ({ ...publicJwk, kty: 'OKP' })],
      ['a missing public key', () => ({ ...publicJwk, pub: undefined })],
      ['a short public key', () => ({ ...publicJwk, pub: 'AA' })],
      ['a signing key', () => ({ ...publicJwk, use: 'sig' })],
      ['incompatible public key operations', () => ({ ...publicJwk, key_ops: ['verify'] })],
    ]) {
      it(`rejects ${label}`, async () => {
        await assert.rejects(HPKE.encrypt(cleartext, key(), { alg }));
      });
    }

    it('rejects a public key for decryption', async () => {
      await assert.rejects(HPKE.decrypt(jwe, publicJwk));
      await assert.rejects(HPKE.decrypt(jwe, keypair.publicKey));
    });

    it('rejects a private key for encryption', async () => {
      await assert.rejects(HPKE.encrypt(cleartext, privateJwk, { alg }));
      await assert.rejects(HPKE.encrypt(cleartext, keypair.privateKey, { alg }));
    });

    it('rejects incompatible private key operations', async () => {
      await assert.rejects(HPKE.decrypt(jwe, { ...privateJwk, key_ops: ['sign'] }));
    });

    it('rejects a malformed private key seed', async () => {
      await assert.rejects(HPKE.decrypt(jwe, { ...privateJwk, priv: 'AA' }));
    });

    it('rejects mismatched public and private JWK material', async () => {
      const pub = Buffer.from(privateJwk.pub, 'base64url');
      pub[0] ^= 1;
      await assert.rejects(HPKE.decrypt(jwe, {
        ...privateJwk, pub: pub.toString('base64url'),
      }));
    });

    it('rejects native keys without the required usages', async () => {
      const wrong = await crypto.subtle.generateKey(algorithms.get(alg).algorithm, false, [
        'encapsulateKey', 'decapsulateKey',
      ]);
      await assert.rejects(HPKE.encrypt(cleartext, wrong.publicKey, { alg }));
      await assert.rejects(HPKE.decrypt(jwe, wrong.privateKey));
    });

    it('rejects native keys for a different algorithm', async () => {
      const wrong = await crypto.subtle.generateKey('X25519', false, ['deriveBits']);
      await assert.rejects(HPKE.encrypt(cleartext, wrong.publicKey, { alg }));
      await assert.rejects(HPKE.decrypt(jwe, wrong.privateKey));
    });
  });
}
