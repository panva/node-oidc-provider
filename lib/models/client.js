'use strict';

/* eslint-disable newline-per-chained-call */

const _ = require('lodash');
const url = require('url');
const crypto = require('crypto');
const jose = require('node-jose');
const assert = require('assert');
const base64url = require('base64url');
const got = require('got');
const uuid = require('uuid').v4;

const epochTime = require('../helpers/epoch_time');
const errors = require('../helpers/errors');
const getSchema = require('../helpers/client_schema');

const NOOP = () => {};
const KEY_ATTRIBUTES = ['crv', 'e', 'kid', 'kty', 'n', 'use', 'x', 'y'];
const KEY_TYPES = ['RSA', 'EC'];

function handled(kty) { return KEY_TYPES.indexOf(kty) !== -1; }

module.exports = function getClient(provider) {
  const Schema = getSchema(provider);
  const cache = new Map();
  const IdToken = provider.IdToken;
  let adapter;

  function getAdapter() {
    if (!adapter) adapter = new (provider.configuration('adapter'))('Client');
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
          assert.ok(res.statusCode === 200,
            `unexpected sector_identifier_uri statusCode, expected 200, got ${res.statusCode}`);
          const body = JSON.parse(res.body);
          assert(Array.isArray(body), 'sector_identifier_uri must return single JSON array');
          const missing = client.redirectUris.find(uri => body.indexOf(uri) === -1);
          assert(!missing,
            'all registered redirect_uris must be included in the sector_identifier_uri');
        } catch (err) {
          throw new errors.InvalidClientMetadata(err.message);
        }

        return client;
      }, (error) => {
        throw new errors.InvalidClientMetadata(
          `could not load sector_identifier_uri (${error.message})`);
      });
    }

    return client;
  }

  function buildKeyStore(client) {
    Object.defineProperty(client, 'keystore', { value: jose.JWK.createKeyStore() });

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

          assert.ok(response.statusCode === 200,
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
            if (handled(key.kty) && kids.indexOf(key.kid) === -1) promises.push(this.remove(key));
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

  class Client {

    backchannelLogout(sub, sid) {
      const logoutToken = new IdToken({ sub }, this.sectorIdentifier);
      logoutToken.mask = { sub: null };
      logoutToken.set('events', ['http://schemas.openid.net/event/backchannel-logout']);
      logoutToken.set('jti', uuid());
      logoutToken.set('sid', sid);

      return logoutToken.sign(this, { noExp: true })
        .then(token => got.post(this.backchannelLogoutUri, provider.httpOptions({
          body: { logout_token: token },
        })).then(NOOP).catch(NOOP));
    }

    responseTypeAllowed(type) {
      return this.responseTypes.indexOf(type) !== -1;
    }

    grantTypeAllowed(type) {
      return this.grantTypes.indexOf(type) !== -1;
    }

    redirectUriAllowed(uri) {
      return this.redirectUris.indexOf(uri) !== -1;
    }

    requestUriAllowed(uri) {
      const parsedUri = url.parse(uri);
      parsedUri.hash = undefined;
      const formattedUri = url.format(parsedUri);

      return !!_.find(this.requestUris, (enabledUri) => {
        const parsedEnabled = url.parse(enabledUri);
        parsedEnabled.hash = undefined;
        return formattedUri === url.format(parsedEnabled);
      });
    }

    postLogoutRedirectUriAllowed(uri) {
      return this.postLogoutRedirectUris.indexOf(uri) !== -1;
    }

    metadata() {
      return _.mapKeys(this, (value, key) => _.snakeCase(key));
    }

    static add(metadata, dynamic) {
      return schemaValidate(new this(), metadata)
        .then(sectorValidate)
        .then(buildKeyStore)
        .then((client) => {
          if (!dynamic) return client;
          return store(client);
        })
        .then(register);
    }

    static remove(id) {
      cache.delete(id);
      return getAdapter().destroy(id);
    }

    static purge() {
      cache.clear();
    }

    static find(id) {
      if (cache.has(id)) return Promise.resolve(cache.get(id));

      return getAdapter().find(id).then((properties) => {
        if (properties) return this.add(properties);
        return undefined;
      });
    }

    static needsSecret(metadata) {
      let clientSecretRequired = metadata.token_endpoint_auth_method === undefined ||
        ['private_key_jwt', 'none'].indexOf(metadata.token_endpoint_auth_method) === -1;

      clientSecretRequired = clientSecretRequired || [
        'id_token_signed_response_alg',
        'request_object_signing_alg',
        'token_endpoint_auth_signing_alg',
        'userinfo_signed_response_alg',
      ].some((prop) => {
        if (metadata[prop] !== undefined && String(metadata[prop]).startsWith('HS')) return true;
        return false;
      });

      clientSecretRequired = clientSecretRequired || [
        'id_token_encrypted_response_alg',
        'userinfo_encrypted_response_alg',
      ].some((prop) => {
        if (metadata[prop] !== undefined && String(metadata[prop]).match(/^(A|P)/)) return true;
        return false;
      });

      return clientSecretRequired;
    }
  }

  return Client;
};
