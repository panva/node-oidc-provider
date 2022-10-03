/* eslint-disable no-plusplus, no-restricted-syntax */
const { importJWK } = require('jose');

const keyscore = (key, { alg, use }) => {
  let score = 0;

  if (alg && key.alg) {
    score++;
  }

  if (use && key.use) {
    score++;
  }

  return score;
};

const getKtyFromJWSAlg = (alg) => {
  switch (alg.slice(0, 2)) {
    case 'RS':
    case 'PS': return 'RSA';
    case 'HS': return 'oct';
    case 'ES': return 'EC';
    case 'Ed': return 'OKP';
    default:
      throw new Error();
  }
};

const getCrvFromJWSAlg = (alg) => {
  switch (alg) {
    case 'ES256': return 'P-256';
    case 'ES256K': return 'secp256k1';
    case 'ES384': return 'P-384';
    case 'ES512': return 'P-521';
    default:
      return undefined;
  }
};

const getKtyFromJWEAlg = (alg, epk) => {
  switch (alg[0]) {
    case 'A':
    case 'P': return 'oct';
    case 'R': return 'RSA';
    case 'E': {
      if (epk && epk.crv.startsWith('X')) {
        return 'OKP';
      }

      if (epk) {
        return 'EC';
      }

      return ['OKP', 'EC'];
    }
    default:
      throw new Error();
  }
};

const selectForDSA = Symbol();
const selectForEncDec = Symbol();
const filter = Symbol();

class KeyStore {
  #keys;

  #cached = new WeakMap();

  constructor(keys = []) {
    this.#keys = keys;
  }

  [selectForDSA](options, operation) {
    const {
      alg,
      kid,
      kty = getKtyFromJWSAlg(alg),
      crv = getCrvFromJWSAlg(alg),
    } = options;

    const scoring = { alg, use: 'sig' };

    return this[filter]((jwk) => {
      let candidate = Array.isArray(kty) ? kty.includes(jwk.kty) : jwk.kty === kty;

      if (candidate && typeof kid === 'string') {
        candidate = kid === jwk.kid;
      }

      if (candidate && typeof jwk.alg === 'string') {
        candidate = alg === jwk.alg;
      }

      if (candidate && typeof jwk.use === 'string') {
        candidate = jwk.use === 'sig';
      }

      if (candidate && crv) {
        candidate = jwk.crv === crv;
      }

      if (candidate && Array.isArray(jwk.key_ops)) {
        candidate = jwk.key_ops.includes(operation);
      }

      if (candidate && alg === 'EdDSA') {
        candidate = ['Ed25519', 'Ed448'].includes(jwk.crv);
      }

      return candidate;
    }, scoring);
  }

  selectForVerify(options) {
    return this[selectForDSA](options, 'verify');
  }

  selectForSign(options) {
    return this[selectForDSA](options, 'sign');
  }

  [selectForEncDec](options, rsa1, rsa2, okp1, okp2) {
    const {
      alg,
      kid,
      epk,
      kty = getKtyFromJWEAlg(alg, epk),
    } = options;

    const scoring = { alg, use: 'enc' };

    return this[filter]((jwk) => {
      let candidate = jwk.kty === kty || (Array.isArray(kty) && kty.includes(jwk.kty));

      if (candidate && typeof kid === 'string') {
        candidate = kid === jwk.kid;
      }

      if (candidate && typeof jwk.alg === 'string') {
        candidate = alg === jwk.alg;
      }

      if (candidate && typeof jwk.use === 'string') {
        candidate = jwk.use === 'enc';
      }

      if (candidate && epk) {
        candidate = epk.crv === jwk.crv;
      }

      if (candidate && Array.isArray(jwk.key_ops)) {
        switch (kty) {
          case 'RSA': {
            if (rsa1 && rsa2) {
              candidate = jwk.key_ops.includes(rsa1) || jwk.key_ops.includes(rsa2);
            }
            break;
          }
          case 'EC':
          case 'OKP': {
            if (okp1 && okp2) {
              candidate = jwk.key_ops.includes(okp1) || jwk.key_ops.includes(okp2);
            }
            break;
          }
          default:
        }
      }

      return candidate;
    }, scoring);
  }

  selectForDecrypt(options) {
    return this[selectForEncDec](options, 'decrypt', 'unwrapKey', 'deriveBits', 'derivekey');
  }

  selectForEncrypt(options) {
    return this[selectForEncDec](options, 'encrypt', 'wrapKey');
  }

  [filter](selector, scoring) {
    return this.#keys
      .filter(selector)
      .sort((first, second) => keyscore(second, scoring) - keyscore(first, scoring));
  }

  add(key) {
    this.#keys.push(key);
  }

  clear() {
    this.#keys = [];
  }

  async getKeyObject(jwk, alg) {
    const cached = this.#cached.get(jwk);
    if (cached) {
      return cached;
    }

    const keyObject = await importJWK({ ...jwk, alg });
    this.#cached.set(jwk, keyObject);
    return keyObject;
  }

  * [Symbol.iterator]() {
    for (const key of this.#keys) {
      yield key;
    }
  }
}

module.exports = KeyStore;
