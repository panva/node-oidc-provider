import * as HPKE from 'hpke';

const definitions = [
  {
    alg: 'HPKE-9',
    kty: 'AKP',
    algorithm: 'MLKEM768-X25519',
    integrated: true,
    kem: HPKE.KEM_MLKEM768_X25519,
    kdf: HPKE.KDF_SHAKE256,
    aead: HPKE.AEAD_AES_256_GCM,
    digest: 'cSHAKE256',
  },
  {
    alg: 'HPKE-12',
    kty: 'AKP',
    algorithm: 'ML-KEM-768',
    integrated: true,
    kem: HPKE.KEM_ML_KEM_768,
    kdf: HPKE.KDF_SHAKE256,
    aead: HPKE.AEAD_AES_256_GCM,
    digest: 'cSHAKE256',
  },
  {
    alg: 'HPKE-13',
    kty: 'AKP',
    algorithm: 'ML-KEM-1024',
    integrated: true,
    kem: HPKE.KEM_ML_KEM_1024,
    kdf: HPKE.KDF_SHAKE256,
    aead: HPKE.AEAD_AES_256_GCM,
    digest: 'cSHAKE256',
  },
];

const entries = new Map();
for (const { kem, kdf, aead, digest, ...definition } of definitions) {
  const suite = new HPKE.CipherSuite(kem, kdf, aead);
  const { Nk, Nn } = suite.AEAD;
  const supported = globalThis.SubtleCrypto?.supports?.('generateKey', definition.algorithm) === true
    && (!digest || globalThis.SubtleCrypto.supports('digest', {
      name: digest, outputLength: (Nk + Nn + suite.KDF.Nh) * 8,
    }) === true);
  entries.set(definition.alg, { ...definition, supported, suite });
}

export const algorithms = [...entries.keys()];
export const supportedAlgorithms = algorithms.filter((alg) => entries.get(alg).supported);
export const get = (alg) => entries.get(alg);
export const isHPKE = (alg) => entries.has(alg);
export const isIntegrated = (alg) => entries.get(alg)?.integrated === true;
