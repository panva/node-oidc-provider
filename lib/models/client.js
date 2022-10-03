/* eslint-disable max-classes-per-file */
const { format, URL } = require('url');
const crypto = require('crypto');
const { STATUS_CODES } = require('http');
const { strict: assert } = require('assert');

const hash = require('object-hash');
const QuickLRU = require('quick-lru');

const KeyStore = require('../helpers/keystore');
const snakeCase = require('../helpers/_/snake_case');
const mapKeys = require('../helpers/_/map_keys');
const camelCase = require('../helpers/_/camel_case');
const isPlainObject = require('../helpers/_/is_plain_object');
const base64url = require('../helpers/base64url');
const request = require('../helpers/request');
const nanoid = require('../helpers/nanoid');
const epochTime = require('../helpers/epoch_time');
const { isConstructable } = require('../helpers/type_validators');
const instance = require('../helpers/weak_cache');
const constantEquals = require('../helpers/constant_equals');
const { InvalidClient, InvalidClientMetadata } = require('../helpers/errors');
const getSchema = require('../helpers/client_schema');
const { 'x5t#S256': x5cThumbprint } = require('../helpers/calculate_thumbprint');
const sectorIdentifier = require('../helpers/sector_identifier');
const { LOOPBACKS } = require('../consts/client_attributes');

// intentionally ignore x5t#S256 so that they are left to be calculated by the library
const EC_CURVES = new Set(['P-256', 'secp256k1', 'P-384', 'P-521']);
const OKP_SUBTYPES = new Set(['Ed25519', 'Ed448', 'X25519', 'X448']);

const backchannel = Symbol();

const fingerprint = (properties) => hash(properties, {
  algorithm: 'sha256',
  ignoreUnknown: true,
  unorderedArrays: true,
});

const validateJWKS = (jwks) => {
  if (jwks !== undefined) {
    if (!Array.isArray(jwks.keys) || !jwks.keys.every(isPlainObject)) {
      throw new InvalidClientMetadata('client JSON Web Key Set is invalid');
    }
  }
};

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

function checkJWK(jwk) {
  try {
    assert(isPlainObject(jwk));
    assert(typeof jwk.kty === 'string' && jwk.kty);

    switch (jwk.kty) {
      case 'EC':
        assert(typeof jwk.crv === 'string' && jwk.crv);
        if (!EC_CURVES.has(jwk.crv)) return undefined;
        assert(typeof jwk.x === 'string' && jwk.x);
        assert(typeof jwk.y === 'string' && jwk.y);
        break;
      case 'OKP':
        assert(typeof jwk.crv === 'string' && jwk.crv);
        if (!OKP_SUBTYPES.has(jwk.crv)) return undefined;
        assert(typeof jwk.x === 'string' && jwk.x);
        break;
      case 'RSA':
        assert(typeof jwk.e === 'string' && jwk.e);
        assert(typeof jwk.n === 'string' && jwk.n);
        break;
      case 'oct':
        break;
      default:
        return undefined;
    }

    assert(jwk.d === undefined && jwk.kty !== 'oct');
    assert(jwk.alg === undefined || (typeof jwk.alg === 'string' && jwk.alg));
    assert(jwk.kid === undefined || (typeof jwk.kid === 'string' && jwk.kid));
    assert(jwk.use === undefined || (typeof jwk.use === 'string' && jwk.use));
    assert(jwk.x5c === undefined || (Array.isArray(jwk.x5c) && jwk.x5c.every((x) => typeof x === 'string' && x)));
  } catch {
    throw new InvalidClientMetadata('client JSON Web Key Set is invalid');
  }

  return jwk;
}

function stripFragment(uri) {
  return format(new URL(uri), { fragment: false });
}

function deriveEncryptionKey(secret, length) {
  const digest = length <= 32 ? 'sha256' : length <= 48 ? 'sha384' : length <= 64 ? 'sha512' : false; // eslint-disable-line no-nested-ternary
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
  const dynamicCache = new QuickLRU({ maxSize: 100 });
  const Schema = getSchema(provider);
  const { IdToken } = provider;
  let adapter;

  function getAdapter() {
    if (!adapter) {
      if (isConstructable(instance(provider).Adapter)) {
        adapter = new (instance(provider).Adapter)('Client');
      } else {
        adapter = instance(provider).Adapter('Client');
      }
    }
    return adapter;
  }

  async function sectorValidate(client) {
    if (!instance(provider).configuration('sectorIdentifierUriValidate')(client)) {
      return;
    }
    const { statusCode, body } = await request.call(provider, {
      method: 'GET',
      url: client.sectorIdentifierUri,
      responseType: 'json',
    }).catch((err) => {
      throw new InvalidClientMetadata('could not load sector_identifier_uri response', err.message);
    });

    if (statusCode !== 200) {
      throw new InvalidClientMetadata(`unexpected sector_identifier_uri response status code, expected 200 OK, got ${statusCode} ${STATUS_CODES[statusCode]}`);
    }

    try {
      assert(Array.isArray(body), 'sector_identifier_uri must return single JSON array');
      if (client.responseTypes.length) {
        const match = client.redirectUris.every((uri) => body.includes(uri));
        assert(
          match,
          'all registered redirect_uris must be included in the sector_identifier_uri response',
        );
      }

      if (
        client.grantTypes.includes('urn:openid:params:grant-type:ciba')
        || client.grantTypes.includes('urn:ietf:params:oauth:grant-type:device_code')
      ) {
        assert(
          body.includes(client.jwksUri),
          "client's jwks_uri must be included in the sector_identifier_uri response",
        );
      }
    } catch (err) {
      throw new InvalidClientMetadata(err.message);
    }
  }

  class ClientKeyStore extends KeyStore {
    #client;

    #provider = provider;

    constructor(clientInstance) {
      super();

      this.#client = clientInstance;
    }

    get client() {
      return this.#client;
    }

    get provider() {
      return this.#provider;
    }

    get jwksUri() {
      return this.client && this.client.jwksUri;
    }

    fresh() {
      if (!this.jwksUri) return true;
      const now = epochTime();
      return !!this.freshUntil && this.freshUntil > now;
    }

    stale() {
      return !this.fresh();
    }

    add(key) {
      if (this.client.tokenEndpointAuthMethod === 'self_signed_tls_client_auth' && Array.isArray(key.x5c) && key.x5c.length) {
        // eslint-disable-next-line no-param-reassign
        key['x5t#S256'] = x5cThumbprint(key.x5c[0]);
      }
      super.add(key);
    }

    async refresh() {
      if (this.fresh()) return;

      if (!this.lock) {
        this.lock = (async () => {
          const { headers, body, statusCode } = await request.call(this.provider, {
            method: 'GET',
            url: this.jwksUri,
            responseType: 'json',
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

          validateJWKS(body);

          this.clear();
          body.keys
            .map(checkJWK)
            .filter(Boolean)
            .forEach(ClientKeyStore.prototype.add.bind(this));

          delete this.lock;
        })().catch((err) => {
          delete this.lock;
          throw new InvalidClientMetadata('client JSON Web Key Set failed to be refreshed', err.error_description || err.message);
        });
      }

      await this.lock;
    }
  }

  function buildAsymmetricKeyStore(client) {
    Object.defineProperty(client, 'asymmetricKeyStore', {
      configurable: true,
      get() {
        const keystore = new ClientKeyStore(this);
        Object.defineProperty(this, 'asymmetricKeyStore', {
          configurable: false,
          value: keystore,
        });

        return this.asymmetricKeyStore;
      },
    });
  }

  function buildSymmetricKeyStore(client) {
    Object.defineProperty(client, 'symmetricKeyStore', {
      configurable: false,
      value: new KeyStore(),
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

      // eslint-disable-next-line no-restricted-syntax
      for (const alg of algs) {
        if (alg.startsWith('HS')) {
          client.symmetricKeyStore.add({
            alg, use: 'sig', kty: 'oct', k: base64url.encode(client.clientSecret),
          });
        } else if (/^A(\d{3})(?:GCM)?KW$/.test(alg)) {
          const len = parseInt(RegExp.$1, 10) / 8;
          client.symmetricKeyStore.add({
            alg, use: 'enc', kty: 'oct', k: deriveEncryptionKey(client.clientSecret, len),
          });
        } else if (/^A(\d{3})(?:GCM|CBC-HS(\d{3}))$/.test(alg)) {
          const len = parseInt(RegExp.$2 || RegExp.$1, 10) / 8;
          client.symmetricKeyStore.add({
            alg, use: 'enc', kty: 'oct', k: deriveEncryptionKey(client.clientSecret, len),
          });
        } else if (alg.startsWith('PBES2')) {
          client.symmetricKeyStore.add({
            alg, use: 'enc', kty: 'oct', k: base64url.encode(client.clientSecret),
          });
        }
      }
    }
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
    #sectorIdentifier = null;

    constructor(metadata, ctx) {
      const schema = new Schema(metadata, ctx);

      Object.assign(this, mapKeys(schema, (value, key) => {
        if (!instance(provider).RECOGNIZED_METADATA.includes(key)) {
          return key;
        }

        return camelCase(key);
      }));

      buildAsymmetricKeyStore(this);
      buildSymmetricKeyStore(this);

      validateJWKS(this.jwks);

      if (this.jwks) {
        this.jwks.keys
          .map(checkJWK)
          .filter(Boolean)
          .forEach(ClientKeyStore.prototype.add.bind(this.asymmetricKeyStore));
      }
    }

    async [backchannel](mode, backchannelAuthenticationRequest, payload) {
      assert(this.backchannelClientNotificationEndpoint);
      assert.equal(this.backchannelTokenDeliveryMode, mode);

      assert(backchannelAuthenticationRequest);
      assert(backchannelAuthenticationRequest.jti);
      assert.equal(backchannelAuthenticationRequest.kind, 'BackchannelAuthenticationRequest');
      assert(backchannelAuthenticationRequest.params.client_notification_token);

      return request.call(provider, {
        method: 'POST',
        url: this.backchannelClientNotificationEndpoint,
        headers: {
          Authorization: `Bearer ${backchannelAuthenticationRequest.params.client_notification_token}`,
        },
        json: { ...payload, auth_req_id: backchannelAuthenticationRequest.jti },
      }).then((response) => {
        const { statusCode } = response;
        if (statusCode !== 204 && statusCode !== 200) {
          const error = new Error(`expected 204 No Content from ${this.backchannelClientNotificationEndpoint}, got: ${statusCode} ${STATUS_CODES[statusCode]}`);
          error.response = response;
          throw error;
        }
      });
    }

    async backchannelPing(backchannelAuthenticationRequest) {
      return this[backchannel]('ping', backchannelAuthenticationRequest);
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
        form: { logout_token: await logoutToken.issue({ use: 'logout' }) },
      }).then((response) => {
        const { statusCode } = response;
        if (statusCode !== 200 && statusCode !== 204) {
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
      if (this.#sectorIdentifier === null) {
        this.#sectorIdentifier = sectorIdentifier(this);
      }

      return this.#sectorIdentifier;
    }

    includeSid() {
      return this.backchannelLogoutUri && this.backchannelLogoutSessionRequired;
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
