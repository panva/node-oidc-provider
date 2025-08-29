/* eslint-disable class-methods-use-this, max-classes-per-file, no-plusplus */

export class ExternalSigningKey {
  #publicJwk;

  #kid;

  #alg;

  get kid() {
    return this.#kid;
  }

  set kid(value) {
    this.#kid = value;
  }

  get alg() {
    return this.#alg;
  }

  set alg(value) {
    this.#alg = value;
  }

  get use() {
    return 'sig';
  }

  #ensurePublicJwk() {
    this.#publicJwk ||= this.keyObject().export({ format: 'jwk' });
  }

  get kty() {
    this.#ensurePublicJwk();
    return this.#publicJwk.kty;
  }

  get pub() {
    this.#ensurePublicJwk();
    return this.#publicJwk.pub;
  }

  get e() {
    this.#ensurePublicJwk();
    return this.#publicJwk.e;
  }

  get n() {
    this.#ensurePublicJwk();
    return this.#publicJwk.n;
  }

  get x() {
    this.#ensurePublicJwk();
    return this.#publicJwk.x;
  }

  get y() {
    this.#ensurePublicJwk();
    return this.#publicJwk.y;
  }

  get crv() {
    this.#ensurePublicJwk();
    return this.#publicJwk.crv;
  }

  get key_ops() {
    return undefined;
  }

  get x5c() {
    return undefined;
  }

  keyObject() {
    throw new Error('not implemented');
  }

  sign() {
    throw new Error('not implemented');
  }
}

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
    case 'ML': return 'AKP';
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
    d, p, q, dp, dq, qi, oth, priv, ...pub
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
      let candidate = jwk.kty === kty;

      if (candidate && typeof kid === 'string') {
        candidate = kid === jwk.kid;
      }

      if (candidate && (typeof jwk.alg === 'string' || kty === 'AKP')) {
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

  getKeyObject(input, getPublic = false) {
    if (input instanceof ExternalSigningKey) {
      return getPublic ? input.keyObject() : input;
    }

    if (input.kty === 'oct' || (!input.d && !input.priv) || !getPublic) {
      return input;
    }

    this.#cachedPub ||= new WeakMap();

    if (!this.#cachedPub.has(input)) {
      this.#cachedPub.set(input, stripPrivate(input));
    }

    return this.#cachedPub.get(input);
  }

  * [Symbol.iterator]() {
    for (const key of this.#keys) {
      yield key;
    }
  }
}

export default KeyStore;
