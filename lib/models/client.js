const _ = require('lodash');
const url = require('url');
const crypto = require('crypto');
const { JWK: { createKeyStore } } = require('node-jose');
const assert = require('assert');
const base64url = require('base64url');
const got = require('got');
const uuid = require('uuid');

const epochTime = require('../helpers/epoch_time');
const instance = require('../helpers/weak_cache');
const { InvalidClientMetadata } = require('../helpers/errors');
const getSchema = require('../helpers/client_schema');

const NOOP = () => {};
const KEY_ATTRIBUTES = ['crv', 'e', 'kid', 'kty', 'n', 'use', 'x', 'y'];
const KEY_TYPES = ['RSA', 'EC'];
const LOOPBACKS = ['localhost', '127.0.0.1', '::1'];

const nonSecretAuthMethods = ['private_key_jwt', 'none'];
const clientEncryptions = [
  'id_token_encrypted_response_alg',
  'userinfo_encrypted_response_alg',
];
const signAlgAttributes = [
  'id_token_signed_response_alg',
  'request_object_signing_alg',
  'token_endpoint_auth_signing_alg',
  'userinfo_signed_response_alg',
];

function isDefinedAndMatches(prop) {
  const value = this[prop];
  return value !== undefined && String(value).match(/^(A|P)/);
}

function isDefinedAndStartsWithHS(prop) {
  const value = this[prop];
  return value !== undefined && String(value).startsWith('HS');
}

function handled(kty) { return KEY_TYPES.includes(kty); }

function stripFragment(uri) {
  return url.format(Object.assign(url.parse(uri), { hash: null }));
}

module.exports = function getClient(provider) {
  const Schema = getSchema(provider);
  const cache = new Map();
  const { IdToken } = provider;
  let adapter;

  function getAdapter() {
    if (!adapter) adapter = new (instance(provider).Adapter)('Client');
    return adapter;
  }

  function schemaValidate(client, metadata) {
    try {
      const schema = new Schema(metadata);

      Object.defineProperty(client, 'sectorIdentifier', { enumerable: false, writable: true });
      Object.assign(client, _.mapKeys(schema, (value, key) => _.camelCase(key)));

      return Promise.resolve(client);
    } catch (err) {
      return Promise.reject(err);
    }
  }

  function sectorValidate(client) {
    if (client.sectorIdentifierUri !== undefined) {
      return got(client.sectorIdentifierUri, provider.httpOptions()).then((res) => {
        try {
          assert.equal(res.statusCode, 200,
            `unexpected sector_identifier_uri statusCode, expected 200, got ${res.statusCode}`);
          const body = JSON.parse(res.body);
          assert(Array.isArray(body), 'sector_identifier_uri must return single JSON array');
          const missing = client.redirectUris.find(uri => !body.includes(uri));
          assert(!missing,
            'all registered redirect_uris must be included in the sector_identifier_uri');
        } catch (err) {
          throw new InvalidClientMetadata(err.message);
        }

        return client;
      }, (error) => {
        throw new InvalidClientMetadata(
          `could not load sector_identifier_uri (${error.message})`);
      });
    }

    return client;
  }

  function buildKeyStore(forClient) {
    const client = forClient;
    Object.defineProperty(client, 'keystore', { value: createKeyStore() });

    client.keystore.fresh = function fresh() {
      if (!this.jwksUri) return true;
      const now = epochTime();
      return this.freshUntil > now;
    };

    client.keystore.stale = function stale() {
      return !this.fresh();
    };

    if (client.jwksUri) {
      client.keystore.jwksUri = client.jwksUri;

      client.keystore.refresh = function refreshKeyStore() {
        return got(this.jwksUri, provider.httpOptions()).then((response) => {
          const expires = Date.parse(response.headers.expires) / 1000;

          if (expires) {
            this.freshUntil = expires;
          } else {
            const cacheControl = response.headers['cache-control'];
            let maxAge = 1 * 60;

            if (cacheControl && cacheControl.match(/max-age=(\d+)/)) {
              maxAge = parseInt(RegExp.$1, 10) || maxAge;
            }

            const now = epochTime();
            this.freshUntil = now + maxAge;
          }

          assert.equal(response.statusCode, 200,
            `unexpected jwks_uri statusCode, expected 200, got ${response.statusCode}`);

          const body = JSON.parse(response.body);

          if (!Array.isArray(body.keys)) throw new Error('invalid jwks_uri response');

          const promises = [];
          const kids = _.map(body.keys, 'kid');

          body.keys.forEach((key) => {
            if (handled(key.kty) && !this.get(key.kid)) {
              promises.push(this.add(_.pick(key, KEY_ATTRIBUTES)));
            }
          });

          this.all().forEach((key) => {
            if (handled(key.kty) && !kids.includes(key.kid)) promises.push(this.remove(key));
          });

          return Promise.all(promises).then(() => this);
        }).catch((err) => {
          throw new Error(`jwks_uri could not be refreshed (${err.message})`);
        });
      };
    }

    const promises = [];

    if (client.jwks && client.jwks.keys) {
      client.jwks.keys.forEach((key) => {
        if (handled(key.kty)) promises.push(client.keystore.add(_.pick(key, KEY_ATTRIBUTES)));
      });
    }

    if (client.keystore.refresh) promises.push(client.keystore.refresh());

    // TODO: DRY the adding of keys;

    return Promise.all(promises).then(() => {
      const symKeys = _.chain(['idTokenEncryptedResponseAlg', 'userinfoEncryptedResponseAlg'])
        .map(prop => client[prop])
        .concat(client.clientSecret ? ['HS256', 'HS384', 'HS512'] : [])
        .uniq()
        .compact()
        .map((alg) => {
          if (alg.match(/^(HS|PBES2)/)) {
            return client.keystore.add({ alg, kty: 'oct', k: base64url(client.clientSecret) });
          } else if (alg.match(/^A.+KW$/)) {
            const len = parseInt(alg.slice(1, 4), 10) / 8;
            const key = crypto.createHash('sha256')
              .update(client.clientSecret)
              .digest()
              .slice(0, len);

            return client.keystore.add({ alg, kty: 'oct', k: base64url(key) });
          }
          return false;
        });

      return Promise.all(symKeys);
    })
      .then(() => client);
  }

  function register(client) {
    cache.set(client.clientId, client);
    return client;
  }

  function store(client) {
    return getAdapter().upsert(client.clientId, client.metadata()).then(() => client);
  }

  function add(metadata, dynamic) {
    return schemaValidate(new Client(), metadata) // eslint-disable-line no-use-before-define
      .then(sectorValidate)
      .then(buildKeyStore)
      .then((client) => {
        if (!dynamic) return client;
        return store(client);
      })
      .then(register);
  }

  function remove(id) {
    cache.delete(id);
    return getAdapter().destroy(id);
  }

  instance(provider).clientAdd = add;
  instance(provider).clientRemove = remove;

  class Client {
    backchannelLogout(sub, sid) {
      const logoutToken = new IdToken({ sub }, this.sectorIdentifier);
      logoutToken.mask = { sub: null };
      logoutToken.set('events', {
        'http://schemas.openid.net/event/backchannel-logout': {},
      });
      logoutToken.set('jti', uuid());
      logoutToken.set('sid', sid);

      return logoutToken.sign(this, { noExp: true })
        .then(token => got.post(this.backchannelLogoutUri, provider.httpOptions({
          form: true,
          body: { logout_token: token },
        })).then(NOOP).catch(NOOP));
    }

    responseTypeAllowed(type) {
      return this.responseTypes.includes(type);
    }

    grantTypeAllowed(type) {
      return this.grantTypes.includes(type);
    }

    redirectUriAllowed(redirectUri) {
      const checkedUri = (() => {
        if (
          this.applicationType === 'native' &&
          redirectUri.startsWith('http:') &&
          instance(provider).configuration('features.oauthNativeApps')
        ) {
          const parsed = url.parse(redirectUri);
          if (LOOPBACKS.includes(parsed.hostname)) {
            return url.format(Object.assign(parsed, {
              host: null,
              port: null,
            }));
          }
        }

        return redirectUri;
      })();


      return this.redirectUris.includes(checkedUri);
    }

    requestUriAllowed(uri) {
      const requested = stripFragment(uri);
      return !!_.find(this.requestUris, enabled => requested === stripFragment(enabled));
    }

    postLogoutRedirectUriAllowed(uri) {
      return this.postLogoutRedirectUris.includes(uri);
    }

    metadata() {
      return _.mapKeys(this, (value, key) => _.snakeCase(key));
    }

    static async find(id, opts) {
      if (cache.has(id)) {
        const found = cache.get(id);
        if (found.noManage || (!opts || !opts.fresh)) return found;
      }
      const properties = await getAdapter().find(id);

      if (properties) return add(properties);
      return undefined;
    }

    static cacheClear() {
      cache.forEach((client) => {
        if (client.noManage) return;
        cache.delete(client.clientId);
      });
    }

    static needsSecret(metadata) {
      if (!nonSecretAuthMethods.includes(metadata.token_endpoint_auth_method)) return true;
      if (!nonSecretAuthMethods.includes(metadata.introspection_endpoint_auth_method) &&
        metadata.introspection_endpoint_auth_method) {
        return true;
      }
      if (!nonSecretAuthMethods.includes(metadata.revocation_endpoint_auth_method) &&
        metadata.revocation_endpoint_auth_method) {
        return true;
      }
      if (signAlgAttributes.some(isDefinedAndStartsWithHS, metadata)) return true;
      if (clientEncryptions.some(isDefinedAndMatches, metadata)) return true;
      return false;
    }
  }

  return Client;
};
