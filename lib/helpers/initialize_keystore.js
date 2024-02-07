import { strict as assert, AssertionError } from 'node:assert';
import { createHash } from 'node:crypto';

import hash from 'object-hash';

import { DEV_KEYSTORE } from '../consts/index.js';

import * as base64url from './base64url.js';
import * as attention from './attention.js';
import instance from './weak_cache.js';
import KeyStore from './keystore.js';

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
    default:
      return undefined;
  }

  return base64url.encodeBuffer(createHash('sha256').update(JSON.stringify(components)).digest());
};
const KEY_TYPES = new Set(['RSA', 'EC', 'OKP']);

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
        case 'secp256k1':
          available = ['ES256K'];
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
        case 'Ed448':
          available = ['EdDSA'];
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
        case 'X448':
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

function registerKey(key, i, keystore) {
  assert(KEY_TYPES.has(key.kty), `only RSA, EC, or OKP keys should be part of jwks configuration (index ${i})`);
  Object.entries(key).forEach(([property, value]) => {
    if (['crv', 'd', 'dp', 'dq', 'e', 'kid', 'kty', 'n', 'p', 'q', 'qi', 'x', 'y', 'use'].includes(property)) {
      assert(typeof value === 'string' && value, `jwks.keys[${i}].${property} configuration must be string`);
    }
    if (['key_ops', 'x5c'].includes(property)) {
      assert(Array.isArray(value) && value.length && value.every((x) => typeof x === 'string' && x), `jwks.keys[${i}].${property} configuration must be an array of strings`);
    }
    switch (key.kty) {
      case 'OKP':
        assert(key.crv && key.x && key.d, `jwks.keys[${i}] configuration is missing required properties`);
        break;
      case 'EC':
        assert(key.crv && key.x && key.y && key.d, `jwks.keys[${i}] configuration is missing required properties`);
        break;
      case 'RSA':
        assert(key.e && key.n && key.d && key.p && key.q && key.dp && key.dq && key.qi, `jwks.keys[${i}] configuration is missing required properties`);
        break;
      default:
    }
  });

  const conf = instance(this).configuration();

  let encryptionAlgs;
  if (conf.features.encryption.enabled) {
    encryptionAlgs = jwkEncryptionAlgorithms(key);

    [
      // 'idTokenEncryptionAlgValues',
      'requestObjectEncryptionAlgValues',
      // 'userinfoEncryptionAlgValues',
    ].forEach((prop) => {
      conf[prop] = [...new Set([...conf[prop], ...encryptionAlgs])]
        .filter((v) => conf.enabledJWA[prop].includes(v));
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
    conf[prop] = [...new Set([...conf[prop], ...signingAlgs])]
      .filter((v) => conf.enabledJWA[prop].includes(v));
  });

  const combined = signingAlgs.concat(encryptionAlgs).filter(Boolean);

  /* eslint-disable no-param-reassign */
  if (combined.length === 1) {
    [key.alg] = combined;
  }

  if ((encryptionAlgs?.length) && !signingAlgs.length) {
    key.use = 'enc';
  } else if (signingAlgs.length && (!encryptionAlgs || !encryptionAlgs.length)) {
    key.use = 'sig';
  }

  if (!Array.isArray(key.x5c) || !key.x5c.length) {
    delete key.x5c;
  }

  assert(combined.length, `jwks.keys[${i}] is of no use given the other configuration, remove it`);
  keystore.add(key);
  /* eslint-enable */
}

export default function initializeKeystore(jwks) {
  if (hash(jwks, { respectType: false }) === hash(DEV_KEYSTORE, { respectType: false })) {
    /* eslint-disable no-multi-str */
    attention.warn('a quick start development-only signing keys are used, you are expected to \
provide your own in configuration "jwks" property');
    /* eslint-enable */
  }

  // eslint-disable-next-line no-undef
  const keystore = new KeyStore();

  let warned;
  const keyIds = new Set();

  try {
    jwks.keys.map(({ ...jwk }) => jwk).forEach((key, i) => {
      // eslint-disable-next-line no-unused-expressions, no-param-reassign
      key.kid ||= calculateKid(key);
      if (!warned && keyIds.has(key.kid)) {
        warned = true;
        /* eslint-disable no-multi-str */
        attention.warn('different keys within the keystore SHOULD use distinct `kid` values, with \
your current keystore you should expect interoperability issues with your clients');
      /* eslint-enable */
      }
      registerKey.call(this, key, i, keystore);
      keyIds.add(key.kid);
    });
  } catch (err) {
    throw new Error(err instanceof AssertionError ? err.message : 'keystore must be a JSON Web Key Set formatted object');
  }

  instance(this).keystore = keystore;
  instance(this).jwksResponse = {
    keys: [...keystore].map((jwk) => ({
      kty: jwk.kty,
      use: jwk.use,
      key_ops: jwk.key_ops ? [...jwk.key_ops] : undefined,
      kid: jwk.kid,
      alg: jwk.alg,
      crv: jwk.crv,
      e: jwk.e,
      n: jwk.n,
      x: jwk.x,
      x5c: jwk.x5c ? [...jwk.x5c] : undefined,
      y: jwk.y,
    })),
  };
}
