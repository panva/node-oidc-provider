/* eslint-disable max-classes-per-file */
import * as crypto from 'node:crypto';
import { STATUS_CODES } from 'node:http';

import KeyStore from '../helpers/keystore.js';
import snakeCase from '../helpers/_/snake_case.js';
import mapKeys from '../helpers/_/map_keys.js';
import camelCase from '../helpers/_/camel_case.js';
import isPlainObject from '../helpers/_/is_plain_object.js';
import * as base64url from '../helpers/base64url.js';
import nanoid from '../helpers/nanoid.js';
import epochTime from '../helpers/epoch_time.js';
import isConstructable from '../helpers/type_validators.js';
import instance from '../helpers/weak_cache.js';
import constantEquals from '../helpers/constant_equals.js';
import { InvalidClient, InvalidClientMetadata } from '../helpers/errors.js';
import certificateThumbprint from '../helpers/certificate_thumbprint.js';
import sectorIdentifier from '../helpers/sector_identifier.js';
import { LOOPBACKS } from '../consts/client_attributes.js';
import sectorValidate from '../helpers/sector_validate.js';
import addClient from '../helpers/add_client.js';
import getSchema from '../helpers/client_schema.js';

// intentionally ignore x5t#S256 so that they are left to be calculated by the library
const EC_CURVES = new Set(['P-256', 'P-384', 'P-521']);
const OKP_SUBTYPES = new Set(['Ed25519', 'X25519']);

const validateJWKS = (jwks) => {
  if (jwks !== undefined) {
    if (!Array.isArray(jwks?.keys) || !jwks.keys.every(isPlainObject)) {
      throw new InvalidClientMetadata('client JSON Web Key Set is invalid');
    }
  }
};

const nonSecretAuthMethods = new Set([
  'private_key_jwt',
  'none',
  'tls_client_auth',
  'self_signed_tls_client_auth',
  'attest_jwt_client_auth',
]);
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
  return /^(A|dir$)/.test(value);
}

function isHmac(prop) {
  const value = this[prop];
  return /^HS/.test(value);
}

function checkJWK(jwk) {
  try {
    if (!(isPlainObject(jwk))) throw new Error();
    if (!(typeof jwk.kty === 'string' && jwk.kty)) throw new Error();

    switch (jwk.kty) {
      case 'EC':
        if (!(typeof jwk.crv === 'string' && jwk.crv)) throw new Error();
        if (!EC_CURVES.has(jwk.crv)) return undefined;
        if (!(typeof jwk.x === 'string' && jwk.x)) throw new Error();
        if (!(typeof jwk.y === 'string' && jwk.y)) throw new Error();
        if (jwk.d !== undefined) throw new Error();
        break;
      case 'OKP':
        if (!(typeof jwk.crv === 'string' && jwk.crv)) throw new Error();
        if (!OKP_SUBTYPES.has(jwk.crv)) return undefined;
        if (!(typeof jwk.x === 'string' && jwk.x)) throw new Error();
        if (jwk.d !== undefined) throw new Error();
        break;
      case 'AKP':
        if (!(typeof jwk.alg === 'string' && jwk.alg)) throw new Error();
        if (!(typeof jwk.pub === 'string' && jwk.pub)) throw new Error();
        if (jwk.priv !== undefined) throw new Error();
        break;
      case 'RSA':
        if (!(typeof jwk.e === 'string' && jwk.e)) throw new Error();
        if (!(typeof jwk.n === 'string' && jwk.n)) throw new Error();
        if (jwk.d !== undefined) throw new Error();
        break;
      case 'oct':
        throw new Error();
      default:
        return undefined;
    }

    if (!(jwk.alg === undefined || (typeof jwk.alg === 'string' && jwk.alg))) throw new Error();
    if (!(jwk.kid === undefined || (typeof jwk.kid === 'string' && jwk.kid))) throw new Error();
    if (!(jwk.use === undefined || (typeof jwk.use === 'string' && jwk.use))) throw new Error();
    if (!(jwk.x5c === undefined || (Array.isArray(jwk.x5c) && jwk.x5c.every((x) => typeof x === 'string' && x)))) throw new Error();
  } catch {
    throw new InvalidClientMetadata('client JSON Web Key Set is invalid');
  }

  return jwk;
}

function deriveEncryptionKey(secret, length) {
  const digest = length <= 32 ? 'sha256' : length <= 48 ? 'sha384' : length <= 64 ? 'sha512' : false; // eslint-disable-line no-nested-ternary
  if (!digest) {
    throw new Error('unsupported symmetric encryption key derivation');
  }
  return crypto.hash(digest, secret, 'buffer').subarray(0, length);
}

export default function getClient(provider) {
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
      return this.client?.jwksUri;
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
      if (this.client.clientAuthMethod === 'self_signed_tls_client_auth' && Array.isArray(key.x5c) && key.x5c.length) {
        // eslint-disable-next-line no-param-reassign
        key['x5t#S256'] = certificateThumbprint(key.x5c[0]);
      }
      super.add(key);
    }

    async refresh() {
      if (this.fresh()) return;

      if (!this.lock) {
        this.lock = (async () => {
          /**
           * @type typeof fetch
           */
          const request = instance(provider).configuration.fetch;
          const response = await request(new URL(this.jwksUri).href, {
            method: 'GET',
            headers: {
              Accept: 'application/json',
            },
          });

          const body = await response.json();
          const { headers, status } = response;

          // min refetch in 60 seconds unless cache headers say a longer response ttl
          const freshUntil = [epochTime() + 60];

          if (headers.has('expires')) {
            freshUntil.push(epochTime(Date.parse(headers.get('expires'))));
          }

          if (headers.has('cache-control') && /max-age=(\d+)/.test(headers.get('cache-control'))) {
            const maxAge = parseInt(RegExp.$1, 10);
            freshUntil.push(epochTime() + maxAge);
          }

          this.freshUntil = Math.max(...freshUntil.filter(Boolean));

          if (status !== 200) {
            throw new Error(`unexpected jwks_uri response status code, expected 200 OK, got ${status} ${STATUS_CODES[status]}`);
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
    const { configuration } = instance(provider);
    Object.defineProperty(client, 'symmetricKeyStore', {
      configurable: false,
      value: new KeyStore(),
    });

    const algs = new Set();

    if (client.clientSecret) {
      if (client.clientAuthMethod === 'client_secret_jwt') {
        if (client.clientAuthSigningAlg) {
          algs.add(client.clientAuthSigningAlg);
        } else {
          configuration.clientAuthSigningAlgValues?.forEach(Set.prototype.add.bind(algs));
        }
      }

      [
        'introspectionSignedResponseAlg',
        'userinfoSignedResponseAlg',
        'authorizationSignedResponseAlg',
        'idTokenSignedResponseAlg',
        'requestObjectSigningAlg',
      ].forEach((prop) => {
        algs.add(client[prop]);
      });

      if (!client.requestObjectSigningAlg) {
        configuration.requestObjectSigningAlgValues.forEach(Set.prototype.add.bind(algs));
      }

      configuration.requestObjectEncryptionAlgValues.forEach(Set.prototype.add.bind(algs));

      if (configuration.requestObjectEncryptionAlgValues.includes('dir')) {
        configuration.requestObjectEncryptionEncValues.forEach(Set.prototype.add.bind(algs));
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

      for (const alg of algs) {
        if (!(
          alg.startsWith('HS')
          || /^A(\d{3})(?:GCM)?KW$/.test(alg)
          || /^A(\d{3})(?:GCM|CBC-HS(\d{3}))$/.test(alg)
        )) {
          algs.delete(alg);
        }
      }

      for (const alg of algs) {
        if (alg.startsWith('HS')) {
          client.symmetricKeyStore.add({
            alg, use: 'sig', kty: 'oct', k: base64url.encode(client.clientSecret),
          });
        } else if (/^A(\d{3})(?:GCM)?KW$/.test(alg)) {
          const len = parseInt(RegExp.$1, 10) / 8;
          client.symmetricKeyStore.add({
            alg, use: 'enc', kty: 'oct', k: deriveEncryptionKey(client.clientSecret, len).toString('base64url'),
          });
        } else if (/^A(\d{3})(?:GCM|CBC-HS(\d{3}))$/.test(alg)) {
          const len = parseInt(RegExp.$2 || RegExp.$1, 10) / 8;
          client.symmetricKeyStore.add({
            alg, use: 'enc', kty: 'oct', k: deriveEncryptionKey(client.clientSecret, len).toString('base64url'),
          });
        }
      }
    }
  }

  class Client {
    #sectorIdentifier = null;

    static #Schema = getSchema(provider);

    static #adapter;

    constructor(metadata, ctx) {
      const schema = new Client.Schema(metadata, ctx);

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

    static get adapter() {
      this.#adapter ||= isConstructable(instance(provider).Adapter)
        ? new (instance(provider).Adapter)('Client')
        : instance(provider).Adapter('Client');
      return this.#adapter;
    }

    async backchannelPing(backchannelAuthenticationRequest) {
      if (
        !this.backchannelClientNotificationEndpoint
        || this.backchannelTokenDeliveryMode !== 'ping'
        || !backchannelAuthenticationRequest
        || !backchannelAuthenticationRequest.jti
        || backchannelAuthenticationRequest.kind !== 'BackchannelAuthenticationRequest'
        || !backchannelAuthenticationRequest.params.client_notification_token
      ) {
        throw new TypeError();
      }

      /**
       * @type typeof fetch
       */
      const request = instance(provider).configuration.fetch;
      return request(new URL(this.backchannelClientNotificationEndpoint).href, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${backchannelAuthenticationRequest.params.client_notification_token}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ auth_req_id: backchannelAuthenticationRequest.jti }),
      }).then((response) => {
        const { status } = response;
        if (status !== 204 && status !== 200) {
          const error = new Error(`expected 204 No Content from ${this.backchannelClientNotificationEndpoint}, got: ${status} ${STATUS_CODES[status]}`);
          error.response = response;
          throw error;
        }
      });
    }

    async backchannelLogout(sub, sid) {
      const logoutToken = new provider.IdToken({ sub }, { client: this, ctx: undefined });
      logoutToken.mask = { sub: null };
      logoutToken.set('events', {
        'http://schemas.openid.net/event/backchannel-logout': {},
      });
      logoutToken.set('jti', nanoid());

      if (this.backchannelLogoutSessionRequired) {
        logoutToken.set('sid', sid);
      }

      /**
       * @type typeof fetch
       */
      const request = instance(provider).configuration.fetch;
      return request(new URL(this.backchannelLogoutUri).href, {
        method: 'POST',
        headers: {
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({ logout_token: await logoutToken.issue({ use: 'logout' }) }),
      }).then((response) => {
        const { status } = response;
        if (status !== 200 && status !== 204) {
          const error = new Error(`expected 200 OK from ${this.backchannelLogoutUri}, got: ${status} ${STATUS_CODES[status]}`);
          error.response = response;
          throw error;
        }
      });
    }

    responseTypeAllowed(type) {
      return this.responseTypes.includes(type);
    }

    // eslint-disable-next-line no-unused-vars
    responseModeAllowed(responseMode, responseType, fapiProfile) {
      if (fapiProfile === '1.0 Final' && !responseType.includes('id_token') && !responseMode.includes('jwt')) {
        return false;
      }

      return this.responseModes?.includes(responseMode) !== false;
    }

    grantTypeAllowed(type) {
      return this.grantTypes.includes(type);
    }

    #redirectAllowed(value, allowedUris) {
      const parsed = URL.parse(value);
      if (!parsed) return false;

      const match = allowedUris.find((allowed) => URL.parse(allowed)?.href === parsed.href);
      if (
        !!match
        || this.applicationType !== 'native'
        || parsed.protocol !== 'http:'
        || !LOOPBACKS.has(parsed.hostname)
      ) {
        return !!match;
      }

      parsed.port = '';

      return !!allowedUris
        .find((allowed) => {
          const registered = URL.parse(allowed);
          if (!registered) return false;
          registered.port = '';
          return parsed.href === registered.href;
        });
    }

    redirectUriAllowed(value) {
      return this.#redirectAllowed(value, this.redirectUris);
    }

    postLogoutRedirectUriAllowed(value) {
      return this.#redirectAllowed(value, this.postLogoutRedirectUris);
    }

    static async validate(metadata) {
      const client = new Client(metadata);

      if (client.sectorIdentifierUri !== undefined) {
        await sectorValidate(provider, client);
      }
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

      const { clockTolerance } = instance(provider).configuration;

      if (epochTime() - clockTolerance >= this.clientSecretExpiresAt) {
        const err = new InvalidClient(message, `client_id ${this.clientId} client_secret expired at ${this.clientSecretExpiresAt}`);
        if (errorOverride) {
          err.error = errorOverride;
          err.message = errorOverride;
        }
        throw err;
      }
    }

    get clientAuthMethod() {
      return this.tokenEndpointAuthMethod;
    }

    get clientAuthSigningAlg() {
      return this.tokenEndpointAuthSigningAlg;
    }

    static async find(id) {
      if (typeof id !== 'string' || !id.length) {
        return undefined;
      }

      const { staticClients, dynamicClients } = instance(provider);

      const cached = staticClients?.get(id);
      if (cached) {
        if (!(cached instanceof Client)) {
          const client = new Client(cached);
          if (client.sectorIdentifierUri !== undefined) {
            await sectorValidate(provider, client);
          }
          Object.defineProperty(client, 'noManage', { value: true });
          staticClients.set(id, client);
          return client;
        }

        return cached;
      }

      const properties = await this.adapter.find(id);

      if (!properties) {
        return undefined;
      }

      const propHash = crypto.hash('sha256', JSON.stringify(properties), 'base64url');
      let client = dynamicClients.get(propHash);

      if (!client) {
        client = await addClient(provider, properties, { store: false });
        dynamicClients.set(propHash, client);
      }

      return client;
    }

    static needsSecret(metadata) {
      if (!nonSecretAuthMethods.has(metadata.token_endpoint_auth_method)) {
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

    static get Schema() {
      return this.#Schema;
    }
  }

  return Client;
}
