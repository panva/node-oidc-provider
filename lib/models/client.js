const { format, URL } = require('url');
const crypto = require('crypto');
const { STATUS_CODES } = require('http');
const { strict: assert } = require('assert');

const hash = require('object-hash');
const jose = require('jose');
const LRU = require('lru-cache');

const pick = require('../helpers/_/pick');
const snakeCase = require('../helpers/_/snake_case');
const mapKeys = require('../helpers/_/map_keys');
const camelCase = require('../helpers/_/camel_case');
const isPlainObject = require('../helpers/_/is_plain_object');
const runtimeSupport = require('../helpers/runtime_support');
const base64url = require('../helpers/base64url');
const request = require('../helpers/request');
const nanoid = require('../helpers/nanoid');
const epochTime = require('../helpers/epoch_time');
const instance = require('../helpers/weak_cache');
const constantEquals = require('../helpers/constant_equals');
const { InvalidClient, InvalidClientMetadata } = require('../helpers/errors');
const getSchema = require('../helpers/client_schema');
const sectorIdentifier = require('../helpers/sector_identifier');
const { LOOPBACKS } = require('../consts/client_attributes');

// intentionally ignore x5t and x5t#S256 so that they are left to be calculated by the jose library
const KEY_ATTRIBUTES = ['crv', 'e', 'kid', 'kty', 'n', 'use', 'key_ops', 'x', 'y'];
const KEY_TYPES = new Set(['RSA', 'EC', 'oct']);
const EC_CURVES = new Set(['P-256', 'secp256k1', 'P-384', 'P-521']);
const OKP_SUBTYPES = new Set(['Ed25519', 'Ed448', 'X25519', 'X448']);

if (runtimeSupport.KeyObject) {
  KEY_TYPES.add('OKP');
  KEY_ATTRIBUTES.push('x5c');
}

const fingerprint = (properties) => hash(properties, {
  algorithm: 'sha256',
  ignoreUnknown: true,
  unorderedArrays: true,
});

const nonSecretAuthMethods = new Set(['private_key_jwt', 'none', 'tls_client_auth', 'self_signed_tls_client_auth']);
const clientEncryptions = [
  'id_token_encrypted_response_alg',
  'request_object_encryption_alg',
  'userinfo_encrypted_response_alg',
  'introspection_encrypted_response_alg',
  'authorization_encrypted_response_alg',
];
const signAlgAttributes = [
  'id_token_signed_response_alg',
  'request_object_signing_alg',
  'token_endpoint_auth_signing_alg',
  'userinfo_signed_response_alg',
  'introspection_signed_response_alg',
  'authorization_signed_response_alg',
];

function isSymmetricAlg(prop) {
  const value = this[prop];
  return /^(A|P|dir$)/.test(value);
}

function isHmac(prop) {
  const value = this[prop];
  return /^HS/.test(value);
}

function checkJWK(prop, jwk, i) {
  if (!isPlainObject(jwk) || typeof jwk.kty !== 'string' || !jwk.kty) {
    throw new Error(`${prop} keys member index ${i} is not a valid JWK`);
  }

  if (!KEY_TYPES.has(jwk.kty)) {
    return undefined;
  }

  switch (jwk.kty) {
    case 'EC':
      if (!EC_CURVES.has(jwk.crv)) {
        return undefined;
      }
      break;
    case 'OKP':
      if (!OKP_SUBTYPES.has(jwk.crv)) {
        return undefined;
      }
      break;
    case 'RSA':
    case 'oct':
      break;
    default:
      return undefined;
  }

  if (jwk.d || jwk.kty === 'oct') { // private RSA, EC, OKP or symmetric keys
    throw new Error(`${prop} must not contain private or symmetric keys (found in keys member index ${i})`);
  }

  try {
    return jose.JWK.asKey(pick(jwk, ...KEY_ATTRIBUTES));
  } catch (err) {
    throw new Error(`${prop} keys member index ${i} is not a valid ${jwk.kty} JWK (${err.message})`);
  }
}

function stripFragment(uri) {
  return format(new URL(uri), { fragment: false });
}

const clientKeyStoreAdditions = {
  setReferences: {
    value(client, provider) {
      instance(this).client = client;
      instance(this).provider = provider;
    },
  },
  client: {
    get() {
      return instance(this).client;
    },
  },
  provider: {
    get() {
      return instance(this).provider;
    },
  },
  jwksUri: {
    get() {
      return this.client && this.client.jwksUri;
    },
  },
  fresh: {
    value() {
      if (!this.jwksUri) return true;
      const now = epochTime();
      return !!this.freshUntil && this.freshUntil > now;
    },
    configurable: true,
  },
  stale: {
    value() {
      return !this.fresh();
    },
  },
  refresh: {
    async value() {
      if (this.fresh()) return;

      if (!this.lock) {
        this.lock = (async () => {
          const { headers, body, statusCode } = await request.call(this.provider, {
            method: 'GET',
            url: this.jwksUri,
            json: true,
          });

          // min refetch in 60 seconds unless cache headers say a longer response ttl
          const freshUntil = [epochTime() + 60];

          if (headers.expires) {
            freshUntil.push(epochTime(Date.parse(headers.expires)));
          }

          if (headers['cache-control'] && /max-age=(\d+)/.test(headers['cache-control'])) {
            const maxAge = parseInt(RegExp.$1, 10);
            freshUntil.push(epochTime() + maxAge);
          }

          this.freshUntil = Math.max(...freshUntil.filter(Boolean));

          if (statusCode !== 200) {
            throw new Error(`unexpected jwks_uri response status code, expected 200 OK, got ${statusCode} ${STATUS_CODES[statusCode]}`);
          }

          if (!Array.isArray(body.keys)) {
            throw new Error('response was not a valid JSON Web Key Set');
          }

          const keyIds = body.keys.map((key) => key.kid);

          body.keys
            .map(checkJWK.bind(undefined, 'jwks_uri'))
            .filter(Boolean)
            .forEach((key) => {
              if (!this.get({ kid: key.kid })) {
                this.add(key);
              }
            });

          for (const key of this) { // eslint-disable-line no-restricted-syntax
            if (key.kty === 'oct') {
              continue; // eslint-disable-line no-continue
            }
            if (!keyIds.includes(key.kid)) {
              this.remove(key);
            }
          }
          delete this.lock;
        })().catch((err) => {
          delete this.lock;
          throw new InvalidClientMetadata(`jwks_uri could not be refreshed (${err.error_description || err.message})`);
        });
      }

      await this.lock;
    },
  },
};

function deriveKey(secret, length) {
  const digest = length <= 32 ? 'sha256' : length <= 48 ? 'sha384' : length <= 64 ? 'sha512' : false; // eslint-disable-line no-nested-ternary
  /* istanbul ignore if */
  if (!digest) {
    throw new Error('unsupported symmetric encryption key derivation');
  }
  const derived = crypto.createHash(digest)
    .update(secret)
    .digest()
    .slice(0, length);
  return base64url.encodeBuffer(derived);
}

module.exports = function getClient(provider) {
  const staticCache = new Map();
  const dynamicCache = new LRU(100);
  const Schema = getSchema(provider);
  const { IdToken } = provider;
  let adapter;

  function getAdapter() {
    if (!adapter) adapter = new (instance(provider).Adapter)('Client');
    return adapter;
  }

  async function sectorValidate(client) {
    try {
      const { statusCode, body } = await request.call(provider, {
        method: 'GET',
        url: client.sectorIdentifierUri,
        json: true,
      }).catch((err) => {
        throw new Error(`could not load sector_identifier_uri (${err.message})`);
      });

      assert.equal(
        statusCode, 200,
        `unexpected sector_identifier_uri response status code, expected 200 OK, got ${statusCode} ${STATUS_CODES[statusCode]}`,
      );
      assert(Array.isArray(body), 'sector_identifier_uri must return single JSON array');
      const missing = client.redirectUris.find((uri) => !body.includes(uri));
      assert(
        !missing,
        'all registered redirect_uris must be included in the sector_identifier_uri',
      );

      return client;
    } catch (err) {
      throw new InvalidClientMetadata(err.message);
    }
  }

  function buildKeyStore(client) {
    Object.defineProperty(client, 'keystore', {
      configurable: true,
      get() {
        const keystore = new jose.JWKS.KeyStore();
        Object.defineProperties(keystore, clientKeyStoreAdditions);
        keystore.setReferences(this, provider);
        Object.defineProperty(this, 'keystore', {
          configurable: false,
          value: keystore,
        });

        const algs = instance(this).lazyAlgs;
        if (algs) {
          const orig = keystore.all;
          Object.defineProperty(keystore, 'all', {
            value(opts) {
              if (opts && opts.alg && algs.has(opts.alg)) {
                let key;
                if (opts.alg.startsWith('HS')) {
                  key = jose.JWK.asKey({
                    alg: opts.alg, use: 'sig', kty: 'oct', k: base64url.encode(this.client.clientSecret),
                  });
                } else if (/^A(\d{3})(?:GCM)?KW$/.test(opts.alg)) {
                  const len = parseInt(RegExp.$1, 10) / 8;
                  key = jose.JWK.asKey({
                    alg: opts.alg, use: 'enc', kty: 'oct', k: deriveKey(this.client.clientSecret, len),
                  });
                } else if (/^A(\d{3})(?:GCM|CBC-HS(\d{3}))$/.test(opts.alg)) {
                  const len = parseInt(RegExp.$2 || RegExp.$1, 10) / 8;
                  key = jose.JWK.asKey({
                    alg: opts.alg, use: 'enc', kty: 'oct', k: deriveKey(this.client.clientSecret, len),
                  });
                } else if (opts.alg.startsWith('PBES2')) {
                  key = jose.JWK.asKey({
                    alg: opts.alg, use: 'enc', kty: 'oct', k: base64url.encode(this.client.clientSecret),
                  });
                }

                algs.delete(opts.alg);
                if (algs.size === 0) {
                  delete instance(client).lazyAlgs;
                }
                this.add(key);
              }

              return orig.call(this, opts);
            },
          });
        }

        return this.keystore;
      },
    });

    const algs = new Set();

    if (client.clientSecret) {
      ['token', 'introspection', 'revocation'].forEach((endpoint) => {
        if (client[`${endpoint}EndpointAuthMethod`] === 'client_secret_jwt') {
          if (client[`${endpoint}EndpointAuthSigningAlg`]) {
            algs.add(client[`${endpoint}EndpointAuthSigningAlg`]);
          } else {
            (instance(provider).configuration(`${endpoint}EndpointAuthSigningAlgValues`) || [])
              .forEach(Set.prototype.add.bind(algs));
          }
        }
      });

      instance(provider).configuration('requestObjectSigningAlgValues').forEach(Set.prototype.add.bind(algs));
      instance(provider).configuration('requestObjectEncryptionAlgValues').forEach(Set.prototype.add.bind(algs));

      if (instance(provider).configuration('requestObjectEncryptionAlgValues').includes('dir')) {
        instance(provider).configuration('requestObjectEncryptionEncValues').forEach(Set.prototype.add.bind(algs));
      }

      [
        'idTokenEncryptedResponse',
        'userinfoEncryptedResponse',
        'introspectionEncryptedResponse',
        'authorizationEncryptedResponse',
      ].forEach((prop) => {
        algs.add(client[`${prop}Alg`]);
        if (client[`${prop}Alg`] === 'dir') {
          algs.add(client[`${prop}Enc`]);
        }
      });

      algs.delete(undefined);

      for (const alg of algs) { // eslint-disable-line no-restricted-syntax
        if (!(
          alg.startsWith('HS')
          || alg.startsWith('PBES2')
          || /^A(\d{3})(?:GCM)?KW$/.test(alg)
          || /^A(\d{3})(?:GCM|CBC-HS(\d{3}))$/.test(alg)
        )) {
          algs.delete(alg);
        }
      }

      if (algs.size) {
        instance(client).lazyAlgs = algs;
      }
    }

    if (client.jwks && client.jwks.keys) {
      try {
        client.jwks.keys
          .map(checkJWK.bind(undefined, 'jwks'))
          .filter(Boolean)
          .forEach((key) => {
            client.keystore.add(key);
          });
      } catch (err) {
        throw new InvalidClientMetadata(err.message);
      }
    }

    return client;
  }

  function addStatic(metadata) {
    if (!isPlainObject(metadata) || !metadata.client_id) {
      throw new InvalidClientMetadata('client_id is mandatory property for statically configured clients');
    }

    if (staticCache.has(metadata.client_id)) {
      throw new InvalidClientMetadata('client_id must be unique amongst statically configured clients');
    }

    staticCache.set(metadata.client_id, JSON.parse(JSON.stringify(metadata)));
  }

  async function add(metadata, { ctx, store = false } = {}) {
    const client = new Client(metadata, ctx); // eslint-disable-line no-use-before-define

    if (client.sectorIdentifierUri !== undefined) {
      await sectorValidate(client);
    }

    if (store) {
      await getAdapter().upsert(client.clientId, client.metadata());
      dynamicCache.set(fingerprint(metadata), client);
    }
    return client;
  }

  function remove(id) {
    return getAdapter().destroy(id);
  }

  instance(provider).clientAdd = add;
  instance(provider).clientAddStatic = addStatic;
  instance(provider).clientRemove = remove;

  class Client {
    constructor(metadata, ctx) {
      const schema = new Schema(metadata, ctx);

      Object.assign(this, mapKeys(schema, (value, key) => {
        if (!instance(provider).RECOGNIZED_METADATA.includes(key)) {
          return key;
        }

        return camelCase(key);
      }));

      buildKeyStore(this);
    }

    async backchannelLogout(sub, sid) {
      const logoutToken = new IdToken({ sub }, { client: this, ctx: undefined });
      logoutToken.mask = { sub: null };
      logoutToken.set('events', {
        'http://schemas.openid.net/event/backchannel-logout': {},
      });
      logoutToken.set('jti', nanoid());

      if (this.backchannelLogoutSessionRequired) {
        logoutToken.set('sid', sid);
      }

      return request.call(provider, {
        method: 'POST',
        url: this.backchannelLogoutUri,
        form: true,
        body: { logout_token: await logoutToken.issue({ use: 'logout' }) },
      }).then((response) => {
        const { statusCode } = response;
        if (statusCode !== 200) {
          const error = new Error(`expected 200 OK from ${this.backchannelLogoutUri}, got: ${statusCode} ${STATUS_CODES[statusCode]}`);
          error.response = response;
          throw error;
        }
      });
    }

    responseTypeAllowed(type) {
      return this.responseTypes.includes(type);
    }

    grantTypeAllowed(type) {
      return this.grantTypes.includes(type);
    }

    redirectUriAllowed(value) {
      let parsed;
      try {
        parsed = new URL(value);
      } catch (err) {
        return false;
      }

      const match = this.redirectUris.includes(value);
      if (
        match
        || this.applicationType !== 'native'
        || parsed.protocol !== 'http:'
        || !LOOPBACKS.has(parsed.hostname)
      ) {
        return match;
      }

      parsed.port = '';

      return !!this.redirectUris
        .find((registeredUri) => {
          const registered = new URL(registeredUri);
          registered.port = '';
          return parsed.href === registered.href;
        });
    }

    checkSessionOriginAllowed(origin) {
      if (!('checkSessionOriginAllowed' in instance(this))) {
        instance(this).checkSessionOriginAllowed = this.redirectUris.reduce((acc, uri) => {
          const { origin: redirectUriOrigin } = new URL(uri);
          acc.add(redirectUriOrigin);
          return acc;
        }, new Set());
      }

      const origins = instance(this).checkSessionOriginAllowed;
      return origins.has(origin);
    }

    webMessageUriAllowed(webMessageUri) {
      return this.webMessageUris && this.webMessageUris.includes(webMessageUri);
    }

    requestUriAllowed(uri) {
      const requested = stripFragment(uri);
      return !!(this.requestUris || []).find((enabled) => requested === stripFragment(enabled));
    }

    postLogoutRedirectUriAllowed(uri) {
      return this.postLogoutRedirectUris.includes(uri);
    }

    metadata() {
      return mapKeys(this, (value, key) => {
        const snaked = snakeCase(key);
        if (!instance(provider).RECOGNIZED_METADATA.includes(snaked)) {
          return key;
        }

        return snaked;
      });
    }

    get sectorIdentifier() {
      if (!('sectorIdentifier' in instance(this))) {
        instance(this).sectorIdentifier = sectorIdentifier(this);
      }
      return instance(this).sectorIdentifier;
    }

    includeSid() {
      return (this.frontchannelLogoutUri && this.frontchannelLogoutSessionRequired)
        || (this.backchannelLogoutUri && this.backchannelLogoutSessionRequired);
    }

    compareClientSecret(actual) {
      return constantEquals(this.clientSecret, actual, 1000);
    }

    checkClientSecretExpiration(message, errorOverride) {
      if (!this.clientSecretExpiresAt) {
        return;
      }

      const clockTolerance = instance(provider).configuration('clockTolerance');

      if (epochTime() - clockTolerance >= this.clientSecretExpiresAt) {
        const err = new InvalidClient(message, `client_id ${this.clientId} client_secret expired at ${this.clientSecretExpiresAt}`);
        if (errorOverride) {
          err.error = errorOverride;
          err.message = errorOverride;
        }
        throw err;
      }
    }

    static async find(id) {
      if (typeof id !== 'string') {
        return undefined;
      }

      if (staticCache.has(id)) {
        const cached = staticCache.get(id);

        if (!(cached instanceof Client)) {
          const client = new Client(cached);
          if (client.sectorIdentifierUri !== undefined) {
            await sectorValidate(client);
          }
          Object.defineProperty(client, 'noManage', { value: true });
          staticCache.set(id, client);
        }

        return staticCache.get(id);
      }

      const properties = await getAdapter().find(id);

      if (!properties) {
        return undefined;
      }

      const propHash = fingerprint(properties);
      let client = dynamicCache.get(propHash);

      if (!client) {
        client = await add(properties, { store: false });
        dynamicCache.set(propHash, client);
      }

      return client;
    }

    static needsSecret(metadata) {
      if (!nonSecretAuthMethods.has(metadata.token_endpoint_auth_method)) {
        return true;
      }

      if (
        !nonSecretAuthMethods.has(metadata.introspection_endpoint_auth_method)
        && metadata.introspection_endpoint_auth_method
      ) {
        return true;
      }

      if (
        !nonSecretAuthMethods.has(metadata.revocation_endpoint_auth_method)
        && metadata.revocation_endpoint_auth_method
      ) {
        return true;
      }

      if (signAlgAttributes.some(isHmac, metadata)) {
        return true;
      }

      if (clientEncryptions.some(isSymmetricAlg, metadata)) {
        return true;
      }

      return false;
    }
  }

  Object.defineProperty(Client, 'Schema', { value: Schema });

  return Client;
};
