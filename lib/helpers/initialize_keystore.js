import { strict as assert } from 'node:assert';
import * as crypto from 'node:crypto';

import { DEV_KEYSTORE } from '../consts/index.js';

import * as attention from './attention.js';
import instance from './weak_cache.js';
import KeyStore, { ExternalSigningKey } from './keystore.js';

const calculateKid = (jwk) => {
  let components;

  switch (jwk.kty) {
    case 'RSA':
      components = {
        e: jwk.e, kty: 'RSA', n: jwk.n,
      };
      break;
    case 'EC':
      components = {
        crv: jwk.crv, kty: 'EC', x: jwk.x, y: jwk.y,
      };
      break;
    case 'OKP':
      components = {
        crv: jwk.crv, kty: 'OKP', x: jwk.x,
      };
      break;
    case 'AKP':
      components = {
        alg: jwk.alg, kty: 'AKP', pub: jwk.pub,
      };
      break;
    default:
      return undefined;
  }

  return crypto.hash('sha256', JSON.stringify(components), 'base64url');
};
const KEY_TYPES = new Set(['RSA', 'EC', 'OKP', 'AKP']);

const jwkSignatureAlgorithms = (jwk) => {
  if (jwk.use !== 'sig' && jwk.use !== undefined) {
    return [];
  }

  let available;

  switch (jwk.kty) {
    case 'RSA':
      available = ['PS256', 'PS384', 'PS512', 'RS256', 'RS384', 'RS512'];
      break;
    case 'EC':
      switch (jwk.crv) {
        case 'P-256':
          available = ['ES256'];
          break;
        case 'P-384':
          available = ['ES384'];
          break;
        case 'P-521':
          available = ['ES512'];
          break;
        default:
      }
      break;
    case 'OKP':
      switch (jwk.crv) {
        case 'Ed25519':
          available = ['EdDSA', 'Ed25519'];
          break;
        default:
      }
      break;
    case 'AKP':
      switch (jwk.alg) {
        case 'ML-DSA-44':
        case 'ML-DSA-65':
        case 'ML-DSA-87':
          available = [jwk.alg];
          break;
        default:
      }
      break;
    default:
  }

  if (jwk.alg) {
    if (available && available.includes(jwk.alg)) {
      return [jwk.alg];
    }
    return [];
  }

  return available || [];
};

const jwkEncryptionAlgorithms = (jwk) => {
  if (jwk.use !== 'enc' && jwk.use !== undefined) {
    return [];
  }

  let available;

  switch (jwk.kty) {
    case 'RSA':
      available = ['RSA-OAEP', 'RSA-OAEP-256', 'RSA-OAEP-384', 'RSA-OAEP-512'];
      break;
    case 'EC':
      switch (jwk.crv) {
        case 'P-256':
        case 'P-384':
        case 'P-521':
          available = ['ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW'];
          break;
        default:
      }
      break;
    case 'OKP':
      switch (jwk.crv) {
        case 'X25519':
          available = ['ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW'];
          break;
        default:
      }
      break;
    default:
  }

  if (jwk.alg) {
    if (available && available.includes(jwk.alg)) {
      return [jwk.alg];
    }
    return [];
  }

  return available || [];
};

function checkString(value, property, i) {
  assert(typeof value === 'string' && value, `jwks.keys[${i}].${property} configuration must be a non-empty string`);
}

function isExternal(key) {
  return key instanceof ExternalSigningKey;
}

function registerKey(input, i, keystore, kids) {
  const { configuration, features } = instance(this);

  let key;
  if (isExternal(input)) {
    assert(features.externalSigningSupport.enabled, 'features.externalSigningSupport must be enabled for ExternalSigningKey support');
    key = input;
  } else {
    key = structuredClone(input);
  }
  assert(KEY_TYPES.has(key.kty), `only RSA, EC, OKP, or AKP keys should be part of jwks configuration (index ${i})`);
  key.kid ??= calculateKid(key);
  checkString(key.kid, 'kid', i);

  assert(!kids.has(key.kid), 'jwks.keys configuration must not contain duplicate "kid" values');
  kids.add(key.kid);

  switch (key.kty) {
    case 'AKP':
      checkString(key.alg, 'alg', i);
      checkString(key.pub, 'pub', i);
      if (!(key instanceof ExternalSigningKey)) {
        checkString(key.priv, 'priv', i);
      }
      break;
    case 'OKP':
      checkString(key.crv, 'crv', i);
      checkString(key.x, 'x', i);
      if (!(key instanceof ExternalSigningKey)) {
        checkString(key.d, 'd', i);
      }
      break;
    case 'EC':
      checkString(key.crv, 'crv', i);
      checkString(key.x, 'x', i);
      checkString(key.y, 'y', i);
      if (!(key instanceof ExternalSigningKey)) {
        checkString(key.d, 'd', i);
      }
      break;
    case 'RSA':
      checkString(key.e, 'e', i);
      checkString(key.n, 'n', i);
      if (!(key instanceof ExternalSigningKey)) {
        checkString(key.d, 'd', i);
        checkString(key.p, 'p', i);
        checkString(key.q, 'q', i);
        checkString(key.dp, 'dp', i);
        checkString(key.dq, 'dq', i);
        checkString(key.qi, 'qi', i);
      }
      break;
    default:
      throw new Error('unreachable');
  }

  if (key instanceof ExternalSigningKey) {
    assert(key.use === 'sig', `jwks.keys[${i}] configuration "use" must be "sig"`);
  }

  if (key.key_ops !== undefined) {
    assert(Array.isArray(key.key_ops) && key.key_ops.length && key.key_ops.every((x) => typeof x === 'string' && x), `jwks.keys[${i}].key_ops configuration must be an array of strings`);
  }

  if (key.x5c !== undefined) {
    assert(Array.isArray(key.x5c) && key.x5c.length && key.x5c.every((x) => typeof x === 'string' && x), `jwks.keys[${i}].x5c configuration must be an array of strings`);
  }

  let encryptionAlgs;
  if (features.encryption.enabled) {
    encryptionAlgs = jwkEncryptionAlgorithms(key);

    [
      // 'idTokenEncryptionAlgValues',
      'requestObjectEncryptionAlgValues',
      // 'userinfoEncryptionAlgValues',
    ].forEach((prop) => {
      configuration[prop] = [...new Set([...configuration[prop], ...encryptionAlgs])]
        .filter((v) => configuration.enabledJWA[prop].includes(v));
    });
  }

  const signingAlgs = jwkSignatureAlgorithms(key);
  [
    'idTokenSigningAlgValues',
    // 'requestObjectSigningAlgValues' uses client's keystore
    // 'tokenEndpointAuthSigningAlgValues' uses client's keystore
    'userinfoSigningAlgValues',
    'introspectionSigningAlgValues',
    'authorizationSigningAlgValues',
  ].forEach((prop) => {
    configuration[prop] = [...new Set([...configuration[prop], ...signingAlgs])]
      .filter((v) => configuration.enabledJWA[prop].includes(v));
  });

  const combined = signingAlgs.concat(encryptionAlgs).filter(Boolean);

  /* eslint-disable no-param-reassign */
  if (combined.length === 1 && key.alg !== combined[0]) {
    [key.alg] = combined;
  }

  if (isExternal(key) && combined.length > 1) {
    checkString(key.alg, 'alg', i);
  }

  if (encryptionAlgs?.length && !signingAlgs.length && key.use !== 'enc') {
    key.use = 'enc';
  } else if (signingAlgs.length && !encryptionAlgs?.length && key.use !== 'sig') {
    key.use = 'sig';
  }

  if (!Array.isArray(key.x5c) || !key.x5c.length) {
    delete key.x5c;
  }

  assert(combined.length, `jwks.keys[${i}] is of no use given the other configuration, remove it`);
  keystore.add(key);
  /* eslint-enable */
}

export default function initialize(jwks) {
  if (jwks === undefined) {
    // eslint-disable-next-line no-param-reassign
    jwks = structuredClone(DEV_KEYSTORE);
    /* eslint-disable no-multi-str */
    attention.warn('a quick start development-only signing keys are used, you are expected to \
provide your own in the configuration "jwks" property');
    /* eslint-enable */
  }

  const keystore = new KeyStore();
  const kids = new Set();

  try {
    if (!Array.isArray(jwks.keys)) {
      throw new Error();
    }
    // eslint-disable-next-line no-plusplus
    for (let i = 0; i < jwks.keys.length; i++) {
      registerKey.call(this, jwks.keys[i], i, keystore, kids);
    }
  } catch (err) {
    throw new Error(err.message || 'keystore must be a JSON Web Key Set formatted object', { cause: err });
  }

  instance(this).keystore = keystore;
  const keys = [...keystore].map((key) => ({
    kty: key.kty,
    use: key.use,
    key_ops: key.key_ops ? [...key.key_ops] : undefined,
    kid: key.kid,
    alg: key.alg,
    crv: key.crv,
    e: key.e,
    n: key.n,
    x: key.x,
    x5c: key.x5c ? [...key.x5c] : undefined,
    y: key.y,
    pub: key.pub,
  }));
  instance(this).jwks = { keys };
}
