const { format, URL } = require('url');
const crypto = require('crypto');
const assert = require('assert');

const _ = require('lodash');
const { JWK: { createKeyStore, asKey } } = require('node-jose');
const LRU = require('lru-cache');
const base64url = require('base64url');
const uuid = require('uuid/v4');

const httpRequest = require('../helpers/http');
const epochTime = require('../helpers/epoch_time');
const instance = require('../helpers/weak_cache');
const { InvalidClientMetadata } = require('../helpers/errors');
const getSchema = require('../helpers/client_schema');
const sectorIdentifier = require('../helpers/sector_identifier');
const { LOOPBACKS } = require('../consts/client_attributes');

const KEY_ATTRIBUTES = ['crv', 'e', 'kid', 'kty', 'n', 'use', 'x', 'y', 'x5c'];
const KEY_TYPES = ['RSA', 'EC'];

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

function handled(kty) { return KEY_TYPES.includes(kty); }

function stripFragment(uri) {
  return format(new URL(uri), { fragment: false });
}

async function validateCertificateChain(jwk) {
  const x5c = jwk.get('x5c');
  if (!Array.isArray(x5c) || !x5c.length) {
    throw new InvalidClientMetadata('when provided, JWK x5c must be non-empty an array');
  }
  const cert = x5c[0];
  const crt = await asKey(Buffer.from(cert, 'base64'), 'x509').catch(() => {
    throw new InvalidClientMetadata('invalid x5c provided');
  });
  switch (jwk.kty) {
    case 'RSA':
      assert(crt.get('n').equals(jwk.get('n')), 'cert and key n mismatch');
      assert(crt.get('e').equals(jwk.get('e')), 'cert and key e mismatch');
      break;
    case 'EC':
      assert.deepEqual(crt.get('crv'), jwk.get('crv'), 'cert and key crv mismatch');
      assert(crt.get('x').equals(jwk.get('x')), 'cert and key x mismatch');
      assert(crt.get('y').equals(jwk.get('y')), 'cert and key y mismatch');
      break;
    default:
  }
}

const JWKStore = createKeyStore().constructor;

Object.defineProperties(JWKStore.prototype, {
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
        const {
          headers,
          body,
          statusCode,
        } = await httpRequest.get(this.jwksUri, this.provider.httpOptions());

        let freshUntil;

        if (freshUntil = Date.parse(headers.expires)) { // eslint-disable-line no-cond-assign
          freshUntil = epochTime(freshUntil);
        } else if (headers['cache-control'] && /max-age=(\d+)/.test(headers['cache-control'])) {
          const maxAge = parseInt(RegExp.$1, 10);
          freshUntil = epochTime() + maxAge;
        } else {
          // TODO: configurable
          freshUntil = epochTime() + 60;
        }

        this.freshUntil = freshUntil;

        assert.deepEqual(
          statusCode, 200,
          `unexpected jwks_uri statusCode, expected 200, got ${statusCode}`,
        );

        const parsedBody = JSON.parse(body);

        if (!Array.isArray(parsedBody.keys)) throw new Error('invalid jwks_uri response');

        const promises = [];
        const kids = parsedBody.keys.map(key => key.kid);

        parsedBody.keys.forEach((key) => {
          if (handled(key.kty) && !this.get(key.kid)) {
            promises.push(this.add(_.pick(key, KEY_ATTRIBUTES)));
          }
        });

        this.all().forEach((key) => {
          if (handled(key.kty) && !kids.includes(key.kid)) promises.push(this.remove(key));
        });

        const keys = await Promise.all(promises);
        await Promise.all(keys.filter((key) => {
          if (key && key.get('x5c')) {
            return true;
          }
          return false;
        }).map(validateCertificateChain));
      } catch (err) {
        throw new InvalidClientMetadata(`jwks_uri could not be refreshed (${err.message})`);
      }
    },
  },
});

module.exports = function getClient(provider) {
  const Schema = getSchema(provider);
  const cache = new LRU();
  const { IdToken } = provider;
  let adapter;

  function getAdapter() {
    if (!adapter) adapter = new (instance(provider).Adapter)('Client');
    return adapter;
  }

  async function schemaValidate(client, metadata) {
    const schema = new Schema(metadata);

    Object.assign(client, _.mapKeys(schema, (value, key) => {
      if (!instance(provider).RECOGNIZED_METADATA.includes(key)) {
        return key;
      }

      return _.camelCase(key);
    }));

    return client;
  }

  async function sectorValidate(client) {
    if (client.sectorIdentifierUri === undefined) return client;

    try {
      const {
        statusCode,
        body,
      } = await httpRequest.get(client.sectorIdentifierUri, provider.httpOptions())
        .catch((err) => {
          throw new Error(`could not load sector_identifier_uri (${err.message})`);
        });

      assert.deepEqual(
        statusCode, 200,
        `unexpected sector_identifier_uri statusCode, expected 200, got ${statusCode}`,
      );
      let parsedBody;
      try {
        parsedBody = JSON.parse(body);
      } catch (err) {
        throw new Error('sector_identifier_uri must return a valid JSON');
      }
      assert(Array.isArray(parsedBody), 'sector_identifier_uri must return single JSON array');
      const missing = client.redirectUris.find(uri => !parsedBody.includes(uri));
      assert(
        !missing,
        'all registered redirect_uris must be included in the sector_identifier_uri',
      );

      return client;
    } catch (err) {
      throw new InvalidClientMetadata(err.message);
    }
  }

  async function buildKeyStore(client) {
    Object.defineProperty(client, 'keystore', { value: createKeyStore() });
    client.keystore.setReferences(client, provider);

    const promises = [];

    if (client.jwks && client.jwks.keys) {
      client.jwks.keys.forEach((key) => {
        if (handled(key.kty)) {
          promises.push(client.keystore.add(_.pick(key, KEY_ATTRIBUTES)));
        }
        return undefined;
      });
    }

    _.chain(['idTokenEncryptedResponseAlg', 'userinfoEncryptedResponseAlg'])
      .map(prop => client[prop])
      .concat(client.clientSecret ? ['HS256', 'HS384', 'HS512'] : [])
      .concat(client.clientSecret ? instance(provider).configuration('requestObjectEncryptionAlgValues') : [])
      .uniq()
      .compact()
      .forEach((alg) => {
        if (alg.startsWith('HS')) {
          promises.push(client.keystore.add({
            alg, use: 'sig', kty: 'oct', k: base64url(client.clientSecret),
          }));
        } else if (/^(?:A|PBES2.+)(\d{3})(?:GCM)?KW$/.test(alg)) {
          const len = parseInt(RegExp.$1, 10) / 8;
          const key = crypto.createHash('sha256')
            .update(client.clientSecret)
            .digest()
            .slice(0, len);

          promises.push(client.keystore.add({
            alg, kty: 'oct', k: base64url(key), use: 'enc',
          }));
        }
        return undefined;
      })
      .value();

    const keys = await Promise.all(promises);
    await Promise.all(keys.filter((key) => {
      if (key && key.get('x5c')) {
        return true;
      }
      return false;
    }).map(validateCertificateChain));

    return client;
  }

  function register(ttl) {
    return (client) => {
      cache.set(client.clientId, client, ttl);
      return client;
    };
  }

  function store(client) {
    return getAdapter().upsert(client.clientId, client.metadata()).then(() => client);
  }

  function add(metadata, dynamic, ttl = instance(provider).configuration('clientCacheDuration') * 1000) {
    return schemaValidate(new Client(), metadata) // eslint-disable-line no-use-before-define
      .then(sectorValidate)
      .then(buildKeyStore)
      .then((client) => {
        if (!dynamic) return client;
        return store(client);
      })
      .then(register(ttl));
  }

  function remove(id) {
    cache.del(id);
    return getAdapter().destroy(id);
  }

  instance(provider).clientAdd = add;
  instance(provider).clientRemove = remove;

  class Client {
    backchannelLogout(sub, sid) {
      const logoutToken = new IdToken({ sub }, this);
      logoutToken.mask = { sub: null };
      logoutToken.set('events', {
        'http://schemas.openid.net/event/backchannel-logout': {},
      });
      logoutToken.set('jti', uuid());
      logoutToken.set('sid', sid);

      return logoutToken.sign({ noExp: true })
        .then(token => httpRequest.post(this.backchannelLogoutUri, provider.httpOptions({
          form: true,
          body: { logout_token: token },
        })));
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
        && instance(provider).configuration('features.oauthNativeApps')
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

    originAllowed(origin) {
      if (!('redirectUriOrigins' in instance(this))) {
        instance(this).redirectUriOrigins = this.redirectUris.reduce((acc, uri) => {
          const { origin: redirectUriOrigin } = new URL(uri);
          acc.add(redirectUriOrigin);
          return acc;
        }, new Set());
      }

      const origins = instance(this).redirectUriOrigins;
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

    /* eslint-disable class-methods-use-this */
    includeSid() {
      return true; // TODO: deprecated
      // return this.frontchannelLogoutSessionRequired || this.backchannelLogoutSessionRequired;
      // return this.frontchannelLogoutUri || this.backchannelLogoutUri;
    }
    /* eslint-enable class-methods-use-this */

    static async find(id, { fresh = false } = {}) {
      if (cache.has(id)) {
        const found = cache.get(id);
        if (found.noManage || (!fresh)) return found;
      }

      const properties = await getAdapter().find(id);

      if (properties) return add(properties);
      return undefined;
    }

    static cacheClear(id) {
      if (id) {
        if (cache.has(id)) {
          const found = cache.get(id);
          if (found.noManage) return;
          cache.del(id);
        }
      } else {
        cache.forEach((client) => {
          if (client.noManage) return;
          cache.del(client.clientId);
        });
      }
    }

    static needsSecret(metadata) {
      if (!nonSecretAuthMethods.includes(metadata.token_endpoint_auth_method)) return true;
      if (!nonSecretAuthMethods.includes(metadata.introspection_endpoint_auth_method)
        && metadata.introspection_endpoint_auth_method) {
        return true;
      }
      if (!nonSecretAuthMethods.includes(metadata.revocation_endpoint_auth_method)
        && metadata.revocation_endpoint_auth_method) {
        return true;
      }
      if (signAlgAttributes.some(isDefinedAndStartsWithHS, metadata)) return true;
      if (clientEncryptions.some(isDefinedAndMatches, metadata)) return true;
      return false;
    }

    static get Schema() {
      return Schema;
    }
  }

  return Client;
};
