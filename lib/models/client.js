const { format, URL } = require('url');
const crypto = require('crypto');
const { STATUS_CODES } = require('http');
const assert = require('assert');

const hash = require('object-hash');
const _ = require('lodash');
const jose = require('@panva/jose');
const LRU = require('lru-cache');
const base64url = require('base64url');

const request = require('../helpers/request');
const nanoid = require('../helpers/nanoid');
const epochTime = require('../helpers/epoch_time');
const instance = require('../helpers/weak_cache');
const { InvalidClientMetadata } = require('../helpers/errors');
const getSchema = require('../helpers/client_schema');
const sectorIdentifier = require('../helpers/sector_identifier');
const { LOOPBACKS } = require('../consts/client_attributes');

// intentionally ignore x5t and x5t#S256 so that they are left to be calculated by the jose library
const KEY_ATTRIBUTES = ['crv', 'e', 'kid', 'kty', 'n', 'use', 'key_ops', 'x', 'y', 'x5c'];
const KEY_TYPES = new Set(['RSA', 'EC', 'OKP']);

const fingerprint = properties => hash(properties, {
  algorithm: 'sha256',
  ignoreUnknown: true,
  unorderedArrays: true,
});

const nonSecretAuthMethods = ['private_key_jwt', 'none', 'tls_client_auth', 'self_signed_tls_client_auth'];
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

function isDefinedAndMatches(prop) {
  const value = this[prop];
  return /^(A|P)/.test(value);
}

function isDefinedAndStartsWithHS(prop) {
  const value = this[prop];
  return /^HS/.test(value);
}

function handled(kty) { return KEY_TYPES.has(kty); }

function stripFragment(uri) {
  return format(new URL(uri), { fragment: false });
}

Object.defineProperties(jose.JWKS.KeyStore.prototype, {
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
      try {
        const { headers, body, statusCode } = await request.call(this.provider, {
          method: 'GET',
          url: this.jwksUri,
          json: true,
        });

        if (statusCode !== 200) {
          throw new Error(`unexpected jwks_uri response status code, expected 200 OK, got ${statusCode} ${STATUS_CODES[statusCode]}`);
        }

        let freshUntil;

        if (freshUntil = Date.parse(headers.expires)) { // eslint-disable-line no-cond-assign
          freshUntil = epochTime(freshUntil);
        } else if (headers['cache-control'] && /max-age=(\d+)/.test(headers['cache-control'])) {
          const maxAge = parseInt(RegExp.$1, 10);
          freshUntil = epochTime() + maxAge;
        } else {
          freshUntil = epochTime() + 60;
        }

        this.freshUntil = freshUntil;

        if (!Array.isArray(body.keys)) {
          throw new Error('invalid jwks_uri response');
        }

        const keyIds = body.keys.map(key => key.kid);

        body.keys
          .filter(jwk => handled(jwk.kty))
          .map((jwk) => {
            if (jwk.d) { // private RSA, EC or OKP keys
              throw new Error('jwks_uri must not contain private keys');
            }

            return _.pick(jwk, KEY_ATTRIBUTES);
          })
          .forEach((jwk) => {
            const key = jose.JWK.importKey(jwk);

            if (!this.get({ kid: key.kid })) {
              this.add(key);
            }
          });

        for (const key of this) { // eslint-disable-line no-restricted-syntax
          if (!keyIds.includes(key.kid)) {
            this.remove(key);
          }
        }
      } catch (err) {
        throw new InvalidClientMetadata(`jwks_uri could not be refreshed (${err.error_description || err.message})`);
      }
    },
  },
});

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

      assert.deepEqual(
        statusCode, 200,
        `unexpected sector_identifier_uri response status code, expected 200 OK, got ${statusCode} ${STATUS_CODES[statusCode]}`,
      );
      assert(Array.isArray(body), 'sector_identifier_uri must return single JSON array');
      const missing = client.redirectUris.find(uri => !body.includes(uri));
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
    Object.defineProperty(client, 'keystore', { value: new jose.JWKS.KeyStore() });
    client.keystore.setReferences(client, provider);

    if (client.jwks && client.jwks.keys) {
      try {
        client.jwks.keys.filter(key => handled(key.kty))
          .map((jwk) => {
            if (jwk.d) { // private
              throw new Error('jwks must not contain private keys');
            }

            return _.pick(jwk, KEY_ATTRIBUTES);
          })
          .forEach((jwk) => {
            const key = jose.JWK.importKey(jwk);
            client.keystore.add(key);
          });
      } catch (err) {
        throw new InvalidClientMetadata(`invalid jwks (${err.message})`);
      }
    }

    const algs = new Set();
    if (client.clientSecret) {
      algs.add('HS');
      instance(provider).configuration('requestObjectEncryptionAlgValues').forEach(Set.prototype.add.bind(algs));
    }
    [client.idTokenEncryptedResponseAlg].forEach(Set.prototype.add.bind(algs));
    [client.userinfoEncryptedResponseAlg].forEach(Set.prototype.add.bind(algs));
    algs.delete(undefined);

    [...algs].forEach((alg) => {
      let key;
      if (alg === 'HS') {
        key = jose.JWK.importKey({
          use: 'sig', kty: 'oct', k: base64url(client.clientSecret),
        });
      } else if (/^A(\d{3})(?:GCM)?KW$/.test(alg)) {
        const len = parseInt(RegExp.$1, 10) / 8;
        const derived = crypto.createHash('sha256')
          .update(client.clientSecret)
          .digest()
          .slice(0, len);

        key = jose.JWK.importKey({
          alg, kty: 'oct', k: base64url(derived), use: 'enc',
        });
      } else if (alg.startsWith('PBES2')) {
        const derived = crypto.createHash('sha256')
          .update(client.clientSecret)
          .digest();

        key = jose.JWK.importKey({
          alg, kty: 'oct', k: base64url(derived), use: 'enc',
        });
      }

      if (key) {
        client.keystore.add(key);
      }
    });

    return client;
  }

  function addStatic(metadata) {
    const client = new Client(metadata); // eslint-disable-line no-use-before-define

    if (client.sectorIdentifierUri !== undefined) {
      throw new Error('statically configured clients may not have sector_identifier_uri');
    }

    staticCache.set(client.clientId, client);
    return client;
  }

  async function add(metadata, { store = false } = {}) {
    const client = new Client(metadata); // eslint-disable-line no-use-before-define

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
    dynamicCache.del(id);
    return getAdapter().destroy(id);
  }

  instance(provider).clientAdd = add;
  instance(provider).clientAddStatic = addStatic;
  instance(provider).clientRemove = remove;

  class Client {
    constructor(metadata) {
      const schema = new Schema(metadata);

      Object.assign(this, _.mapKeys(schema, (value, key) => {
        if (!instance(provider).RECOGNIZED_METADATA.includes(key)) {
          return key;
        }

        return _.camelCase(key);
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
        body: { logout_token: await logoutToken.issue({ noExp: true }) },
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

    redirectUriAllowed(redirectUri) {
      let checkedUri = redirectUri;
      if (
        this.applicationType === 'native'
        && redirectUri.startsWith('http:')
      ) {
        try {
          const parsed = new URL(redirectUri);
          if (LOOPBACKS.includes(parsed.hostname)) {
            parsed.port = 80;
            checkedUri = parsed.href;
          }
        } catch (err) {}
      }

      return this.redirectUris.includes(checkedUri);
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
      return !!_.find(this.requestUris, enabled => requested === stripFragment(enabled));
    }

    postLogoutRedirectUriAllowed(uri) {
      return this.postLogoutRedirectUris.includes(uri);
    }

    metadata() {
      return _.mapKeys(this, (value, key) => {
        const snaked = _.snakeCase(key);
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

    static async find(id) {
      if (typeof id !== 'string') {
        return undefined;
      }

      if (staticCache.has(id)) {
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
      if (!nonSecretAuthMethods.includes(metadata.token_endpoint_auth_method)) {
        return true;
      }

      if (
        !nonSecretAuthMethods.includes(metadata.introspection_endpoint_auth_method)
        && metadata.introspection_endpoint_auth_method
      ) {
        return true;
      }

      if (
        !nonSecretAuthMethods.includes(metadata.revocation_endpoint_auth_method)
        && metadata.revocation_endpoint_auth_method
      ) {
        return true;
      }

      if (signAlgAttributes.some(isDefinedAndStartsWithHS, metadata)) {
        return true;
      }

      if (clientEncryptions.some(isDefinedAndMatches, metadata)) {
        return true;
      }

      return false;
    }
  }

  Object.defineProperty(Client, 'Schema', { value: Schema });

  return Client;
};
