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

function check(condition, message, cause) {
  if (!condition) {
    throw new Error(message, { cause });
  }
}

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
    if (available?.includes(jwk.alg)) {
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
    if (available?.includes(jwk.alg)) {
      return [jwk.alg];
    }
    return [];
  }

  return available || [];
};

function isExternal(key) {
  return key instanceof ExternalSigningKey;
}

function registerKey(input, i, keystore, kids) {
  const { configuration, features } = instance(this);

  let key;
  if (isExternal(input)) {
    check(
      features.externalSigningSupport.enabled,
      'features.externalSigningSupport must be enabled for ExternalSigningKey support',
      input,
    );
    key = input;
  } else {
    key = structuredClone(input);
  }

  const checkKey = (condition, message) => check(condition, message, input);
  const checkString = (property) => checkKey(
    typeof key?.[property] === 'string' && key[property],
    `jwks.keys[${i}].${property} configuration must be a non-empty string`,
  );

  checkKey(KEY_TYPES.has(key?.kty), `only RSA, EC, OKP, or AKP keys should be part of jwks configuration (index ${i})`);
  key.kid ??= calculateKid(key);
  checkString('kid');

  checkKey(!kids.has(key.kid), 'jwks.keys configuration must not contain duplicate "kid" values');
  kids.add(key.kid);

  switch (key.kty) {
    case 'AKP':
      checkString('alg');
      checkString('pub');
      if (!(key instanceof ExternalSigningKey)) {
        checkString('priv');
      }
      break;
    case 'OKP':
      checkString('crv');
      checkString('x');
      if (!(key instanceof ExternalSigningKey)) {
        checkString('d');
      }
      break;
    case 'EC':
      checkString('crv');
      checkString('x');
      checkString('y');
      if (!(key instanceof ExternalSigningKey)) {
        checkString('d');
      }
      break;
    case 'RSA':
      checkString('e');
      checkString('n');
      if (!(key instanceof ExternalSigningKey)) {
        for (const parameter of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
          checkString(parameter);
        }
      }
      break;
    default:
      throw new Error('unreachable');
  }

  if (key instanceof ExternalSigningKey) {
    checkKey(key.use === 'sig', `jwks.keys[${i}] configuration "use" must be "sig"`);
  }

  if (key.key_ops !== undefined) {
    checkKey(
      Array.isArray(key.key_ops) && key.key_ops.length && key.key_ops.every((x) => typeof x === 'string' && x),
      `jwks.keys[${i}].key_ops configuration must be an array of strings`,
    );
  }

  if (key.x5c !== undefined) {
    checkKey(
      Array.isArray(key.x5c) && key.x5c.length && key.x5c.every((x) => typeof x === 'string' && x),
      `jwks.keys[${i}].x5c configuration must be an array of strings`,
    );
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

  if (combined.length === 1 && key.alg !== combined[0]) {
    [key.alg] = combined;
  }

  if (isExternal(key) && combined.length > 1) {
    checkString('alg');
  }

  if (encryptionAlgs?.length && !signingAlgs.length && key.use !== 'enc') {
    key.use = 'enc';
  } else if (signingAlgs.length && !encryptionAlgs?.length && key.use !== 'sig') {
    key.use = 'sig';
  }

  if (!Array.isArray(key.x5c) || !key.x5c.length) {
    delete key.x5c;
  }

  checkKey(combined.length, `jwks.keys[${i}] is of no use given the other configuration, remove it`);
  keystore.add(key);
}

export default function initialize(jwks) {
  if (jwks === undefined) {
    jwks = structuredClone(DEV_KEYSTORE);
    attention.warn('quick start development-only signing keys are used, you are expected to \
provide your own in the configuration "jwks" property');
  }

  const keystore = new KeyStore();
  const kids = new Set();

  check(
    jwks !== null && typeof jwks === 'object' && Array.isArray(jwks.keys),
    'keystore must be a JSON Web Key Set formatted object',
    jwks,
  );
  for (let i = 0; i < jwks.keys.length; i++) {
    registerKey.call(this, jwks.keys[i], i, keystore, kids);
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
