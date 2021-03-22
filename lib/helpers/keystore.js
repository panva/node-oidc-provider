/* eslint-disable no-plusplus, no-restricted-syntax, symbol-description */
const { parseJwk } = require('jose/jwk/parse'); // eslint-disable-line import/no-unresolved

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
  switch (alg.substr(0, 2)) {
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
  switch (alg.substr(0, 1)) {
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
  #jwks;

  #keyObjects = new WeakMap();

  constructor(jwks = []) {
    this.#jwks = jwks;
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
      let candidate = jwk.kty === kty;

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
    return this.#jwks
      .filter(selector)
      .sort((first, second) => keyscore(second, scoring) - keyscore(first, scoring));
  }

  add(key) {
    this.#jwks.push(key);
  }

  clear() {
    this.#jwks = [];
  }

  async getKeyObject(jwk, alg) {
    const cached = this.#keyObjects.get(jwk);
    if (cached) {
      cached.i = (cached.i + 1) % 4;
      return cached[cached.i];
    }

    const keyObjects = await Promise.all([
      parseJwk({ ...jwk, alg }),
      parseJwk({ ...jwk, alg }),
      parseJwk({ ...jwk, alg }),
      parseJwk({ ...jwk, alg }),
    ]);
    keyObjects.i = 0;
    this.#keyObjects.set(jwk, keyObjects);
    return keyObjects[keyObjects.i];
  }

  * [Symbol.iterator]() {
    for (const key of this.#jwks) {
      yield key;
    }
  }
}

module.exports = KeyStore;
