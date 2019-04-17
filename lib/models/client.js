const { format, URL } = require('url');
const crypto = require('crypto');
const assert = require('assert');

const hash = require('object-hash');
const _ = require('lodash');
const jose = require('@panva/jose');
const LRU = require('lru-cache');
const base64url = require('base64url');

const nanoid = require('../helpers/nanoid');
const httpRequest = require('../helpers/http');
const epochTime = require('../helpers/epoch_time');
const instance = require('../helpers/weak_cache');
const { InvalidClientMetadata } = require('../helpers/errors');
const getSchema = require('../helpers/client_schema');
const sectorIdentifier = require('../helpers/sector_identifier');
const { LOOPBACKS } = require('../consts/client_attributes');
const { X5C } = require('../helpers/symbols');

const KEY_ATTRIBUTES = ['crv', 'e', 'kid', 'kty', 'n', 'use', 'x', 'y', 'x5c'];
const KEY_TYPES = new Set(['RSA', 'EC']);

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

function validateCertificateChain(jwk) {
  const x5c = jwk[X5C];
  if (!Array.isArray(x5c) || !x5c.length) {
    throw new InvalidClientMetadata('when provided, JWK x5c must be non-empty an array');
  }
  const cert = x5c[0];
  let crt;
  try {
    const keyObject = crypto.createPublicKey({
      key: `-----BEGIN CERTIFICATE-----\n${cert}\n-----END CERTIFICATE-----`,
      format: 'pem',
    });
    crt = jose.JWK.importKey(keyObject);
  } catch (err) {
    throw new InvalidClientMetadata('invalid x5c provided');
  }
  switch (jwk.kty) {
    case 'RSA':
      assert.equal(crt.n, jwk.n, 'cert and key n mismatch');
      assert.equal(crt.e, jwk.e, 'cert and key e mismatch');
      break;
    case 'EC':
      assert.equal(crt.crv, jwk.crv, 'cert and key crv mismatch');
      assert.equal(crt.x, jwk.x, 'cert and key x mismatch');
      assert.equal(crt.y, jwk.y, 'cert and key y mismatch');
      break;
    default:
  }
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
          freshUntil = epochTime() + 60;
        }

        this.freshUntil = freshUntil;

        assert.deepEqual(
          statusCode, 200,
          `unexpected jwks_uri statusCode, expected 200, got ${statusCode}`,
        );

        const parsedBody = JSON.parse(body);

        if (!Array.isArray(parsedBody.keys)) {
          throw new Error('invalid jwks_uri response');
        }

        const kids = parsedBody.keys.map(key => key.kid);

        parsedBody.keys
          .filter(jwk => handled(jwk.kty))
          .map((jwk) => {
            if (jwk.d) { // private RSA or EC
              throw new Error('jwks_uri must not contain private keys');
            }

            return _.pick(jwk, KEY_ATTRIBUTES);
          })
          .forEach((jwk) => {
            const key = jose.JWK.importKey(jwk);
            if ('x5c' in jwk) {
              key[X5C] = jwk.x5c;
            }

            if (!this.get({ kid: key.kid })) {
              this.add(key);
            }
          });

        this.all().forEach((key) => {
          if (handled(key.kty) && !kids.includes(key.kid)) {
            this.remove(key);
          }
        });

        this.all().filter((key) => {
          if (key && X5C in key) {
            return true;
          }
          return false;
        }).map(validateCertificateChain);
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

  function buildKeyStore(client) {
    Object.defineProperty(client, 'keystore', { value: new jose.JWKS.KeyStore() });
    client.keystore.setReferences(client, provider);

    const keys = [];

    if (client.jwks && client.jwks.keys) {
      client.jwks.keys.filter(key => handled(key.kty))
        .map((jwk) => {
          if (jwk.d) { // private RSA or EC
            throw new InvalidClientMetadata('jwks must not contain private keys');
          }

          return _.pick(jwk, KEY_ATTRIBUTES);
        })
        .forEach((jwk) => {
          const key = jose.JWK.importKey(jwk);
          keys.push(key);
          if ('x5c' in jwk) {
            key[X5C] = jwk.x5c;
          }
          client.keystore.add(key);
        });
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
        keys.push(key);
        client.keystore.add(key);
      }
    });

    keys.forEach((key) => {
      if (key && X5C in key) {
        validateCertificateChain(key);
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

    backchannelLogout(sub, sid) {
      const logoutToken = new IdToken({ sub }, { client: this, ctx: undefined });
      logoutToken.mask = { sub: null };
      logoutToken.set('events', {
        'http://schemas.openid.net/event/backchannel-logout': {},
      });
      logoutToken.set('jti', nanoid());

      if (this.backchannelLogoutSessionRequired) {
        logoutToken.set('sid', sid);
      }

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
  }

  Object.defineProperty(Client, 'Schema', { value: Schema });

  return Client;
};
