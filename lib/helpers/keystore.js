/* eslint-disable no-plusplus */

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
  switch (alg.substring(0, 2)) {
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
    case 'ES384': return 'P-384';
    case 'ES512': return 'P-521';
    case 'EdDSA':
    case 'Ed25519': return 'Ed25519';
    default:
      return undefined;
  }
};

const getKtyFromJWEAlg = (alg, epk) => {
  switch (alg[0]) {
    case 'A': return 'oct';
    case 'R': return 'RSA';
    case 'E': {
      if (epk) {
        return epk.crv.startsWith('X') ? 'OKP' : 'EC';
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

function stripPrivate(jwk) {
  const {
    d, p, q, dp, dq, qi, oth, ...pub
  } = jwk;
  return pub;
}

class KeyStore {
  #keys;

  #cachedPub;

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
      let candidate = typeof kty === 'string' ? jwk.kty === kty : kty.includes(jwk.kty);

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

      return candidate;
    }, scoring);
  }

  selectForVerify(options) {
    return this[selectForDSA](options, 'verify');
  }

  selectForSign(options) {
    return this[selectForDSA](options, 'sign');
  }

  [selectForEncDec](options, operation) {
    const {
      alg,
      kid,
      epk,
      kty = getKtyFromJWEAlg(alg, epk),
    } = options;

    const scoring = { alg, use: 'enc' };

    return this[filter]((jwk) => {
      let candidate = Array.isArray(kty) ? kty.includes(jwk.kty) : jwk.kty === kty;

      if (candidate && kid !== undefined) {
        candidate = kid === jwk.kid;
      }

      if (candidate && jwk.alg !== undefined) {
        candidate = alg === jwk.alg;
      }

      if (candidate && jwk.use !== undefined) {
        candidate = jwk.use === 'enc';
      }

      if (candidate && epk) {
        candidate = epk.crv === jwk.crv;
      }

      if (candidate && Array.isArray(jwk.key_ops)) {
        switch (kty) {
          case 'RSA': {
            candidate = jwk.key_ops.includes(operation);
            break;
          }
          case 'EC':
          case 'OKP': {
            if (operation === 'decrypt') candidate = jwk.key_ops.includes('deriveBits');
            break;
          }
          default:
        }
      }

      return candidate;
    }, scoring);
  }

  selectForDecrypt(options) {
    return this[selectForEncDec](options, 'decrypt');
  }

  selectForEncrypt(options) {
    return this[selectForEncDec](options, 'encrypt');
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

  getKeyObject(jwk, getPublic = false) {
    if (jwk.kty === 'oct' || !jwk.d || !getPublic) {
      return jwk;
    }

    this.#cachedPub ||= new WeakMap();

    if (!this.#cachedPub.has(jwk)) {
      this.#cachedPub.set(jwk, stripPrivate(jwk));
    }

    return this.#cachedPub.get(jwk);
  }

  * [Symbol.iterator]() {
    for (const key of this.#keys) {
      yield key;
    }
  }
}

export default KeyStore;
