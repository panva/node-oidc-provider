/* eslint-disable newline-per-chained-call */
'use strict';

const _ = require('lodash');
const validUrl = require('valid-url');
const url = require('url');
const jose = require('node-jose');
const assert = require('assert');
const base64url = require('base64url');
const got = require('got');

const errors = require('../helpers/errors');
const KEY_ATTRIBUTES = ['crv', 'e', 'kid', 'kty', 'n', 'use', 'x', 'y'];

const KEY_TYPES = ['RSA', 'EC'];
const RECOGNIZED_METADATA = [
  'application_type',
  'client_id',
  'client_name',
  'client_secret',
  'client_secret_expires_at',
  'client_uri',
  'contacts',
  'default_acr_values',
  'default_max_age',
  'grant_types',
  'id_token_encrypted_response_alg',
  'id_token_encrypted_response_enc',
  'id_token_signed_response_alg',
  'initiate_login_uri',
  'jwks',
  'jwks_uri',
  'logo_uri',
  'policy_uri',
  'post_logout_redirect_uris',
  'redirect_uris',
  'registration_access_token',
  'request_object_encryption_alg',
  'request_object_encryption_enc',
  'request_object_signing_alg',
  'request_uris',
  'require_auth_time',
  'response_types',
  'sector_identifier_uri',
  'subject_type',
  'token_endpoint_auth_method',
  'token_endpoint_auth_signing_alg',
  'tos_uri',
  'userinfo_encrypted_response_alg',
  'userinfo_encrypted_response_enc',
  'userinfo_signed_response_alg',
];

const SECRET_LENGTH_REQUIRED = [
  'id_token_signed_response_alg',
  'request_object_signing_alg',
  'token_endpoint_auth_signing_alg',
  'userinfo_signed_response_alg',
];

module.exports = function getClient(provider) {
  const REQUIRED = [
    'client_id',
    'client_secret',
    'redirect_uris',
  ];

  const BOOL = [
    'require_auth_time',
  ];

  const ENUM = {
    application_type: ['native', 'web'],
    response_types: provider.configuration('responseTypes'),
    default_acr_values: provider.configuration('acrValues'),
    grant_types: provider.configuration('grantTypes'),
    subject_type: provider.configuration('subjectTypes'),
    token_endpoint_auth_method: provider.configuration('tokenEndpointAuthMethods'),
    userinfo_signed_response_alg: () => provider.configuration('userinfoSigningAlgValues'),
    id_token_signed_response_alg: (metadata) => {
      if (metadata.response_types.join(' ').indexOf('token') === -1) {
        return provider.configuration('idTokenSigningAlgValues');
      }
      return _.without(provider.configuration('idTokenSigningAlgValues'), 'none');
    },
    id_token_encrypted_response_alg: provider.configuration('idTokenEncryptionAlgValues'),
    id_token_encrypted_response_enc: provider.configuration('idTokenEncryptionEncValues'),
    userinfo_encrypted_response_alg: provider.configuration('userinfoEncryptionAlgValues'),
    userinfo_encrypted_response_enc: provider.configuration('userinfoEncryptionEncValues'),
    request_object_encryption_alg: () => provider.configuration('requestObjectEncryptionAlgValues'),
    request_object_encryption_enc: provider.configuration('requestObjectEncryptionEncValues'),
  };

  const ARYS = [
    'contacts',
    'default_acr_values',
    'grant_types',
    'redirect_uris',
    'post_logout_redirect_uris',
    'request_uris',
    'response_types',
  ];

  const STRING = [
    'application_type',
    'client_id',
    'client_name',
    'client_secret',
    'id_token_signed_response_alg',
    'sector_identifier_uri',
    'subject_type',
    'token_endpoint_auth_method',
    'userinfo_signed_response_alg',
    'id_token_encrypted_response_alg',
    'request_object_signing_alg',
    'id_token_encrypted_response_enc',
    'userinfo_encrypted_response_alg',
    'userinfo_encrypted_response_enc',
    'request_object_encryption_enc',
    'request_object_encryption_alg',
    'client_uri',
    'initiate_login_uri',
    'jwks_uri',
    'logo_uri',
    'policy_uri',
    'tos_uri',

    // in arrays
    'contacts',
    'default_acr_values',
    'grant_types',
    'redirect_uris',
    'post_logout_redirect_uris',
    'request_uris',
    'response_types',
  ];

  const WHEN = {
    id_token_encrypted_response_enc: ['id_token_encrypted_response_alg', 'A128CBC-HS256'],
    userinfo_encrypted_response_enc: ['userinfo_encrypted_response_alg', 'A128CBC-HS256'],
    request_object_encryption_enc: ['request_object_encryption_alg', 'A128CBC-HS256'], // eslint-disable-line
  };

  const WEB_URI = [
    'client_uri',
    'initiate_login_uri',
    'jwks_uri',
    'logo_uri',
    'policy_uri',
    'tos_uri',
    'sector_identifier_uri',

    // in arrays
    'post_logout_redirect_uris',
    'request_uris',
  ];

  const LENGTH = [
    'grant_types',
    'redirect_uris',
    'response_types',
  ];

  const DEFAULT = {
    application_type: 'web',
    grant_types: ['authorization_code'],
    id_token_signed_response_alg: 'RS256',
    post_logout_redirect_uris: [],
    request_uris: provider.configuration('features.requestUri.requireRequestUriRegistration') ?
      [] : undefined,
    require_auth_time: false,
    response_types: ['code'],
    subject_type: 'public',
    token_endpoint_auth_method: 'client_secret_basic',
  };

  class Schema {
    constructor(metadata) {
      _.assign(this, DEFAULT);
      Object.assign(this,
        _.chain(metadata).omitBy(_.isNull).pick(RECOGNIZED_METADATA).value());

      this.required();
      this.whens();
      this.arrays();
      this.lengths();
      this.strings();
      this.enums();
      this.booleans();
      this.webUris();
      this.redirectUris();

      // MAX AGE FORMAT
      if (this.default_max_age !== undefined) {
        if (!Number.isInteger(this.default_max_age) || this.default_max_age <= 0) {
          throw new errors.InvalidClientMetadata('default_max_age must be a positive integer');
        }
      }

      const rts = _.chain(this.response_types).map(rt => rt.split(' '))
        .flatten().uniq().value();

      if (_.includes(rts, 'code')) {
        if (this.grant_types.indexOf('authorization_code') === -1) {
          throw new errors.InvalidClientMetadata(
            'grant_types must contain authorization_code when code is amongst response_types');
        }
      }

      if (_.includes(rts, 'token') || _.includes(rts, 'id_token')) {
        if (this.grant_types.indexOf('implicit') === -1) {
          throw new errors.InvalidClientMetadata(
            'grant_types must contain implicit when id_token or token are amongst response_types');
        }
      }

      // CLIENT SECRET LENGHT
      const hsLengths = SECRET_LENGTH_REQUIRED.map((prop) => {
        if (this[prop] && this[prop].startsWith('HS')) {
          return parseInt(this[prop].slice(-3) / 8, 10);
        }

        return undefined;
      });

      const validateSecretLength = _.max(hsLengths);

      if (validateSecretLength) {
        if (this.client_secret.length < validateSecretLength) {
          throw new errors.InvalidClientMetadata('insufficient client_secret length');
        }
      }

      // PAIRWISE PRESENCE
      if (this.subject_type === 'pairwise' && !this.sector_identifier_uri) {
        const hosts = _.chain(this.redirect_uris)
          .map(uri => url.parse(uri).host).uniq().value();

        if (hosts.length === 1) {
          this.sector_identifier = hosts[0];
        } else {
          throw new errors.InvalidClientMetadata(
            'sector_identifier_uri is required when using multiple hosts in your redirect_uris'
          );
        }
      } else if (this.sector_identifier_uri) {
        this.sector_identifier = url.parse(this.sector_identifier_uri).host;
      }
    }

    required() {
      REQUIRED.forEach((prop) => {
        if (!this[prop]) {
          throw new errors.InvalidClientMetadata(`${prop} is mandatory property`);
        }
      });
    }

    strings() {
      STRING.forEach((prop) => {
        if (this[prop] !== undefined) {
          const isAry = ARYS.indexOf(prop) !== -1;
          (isAry ? this[prop] : [this[prop]]).forEach((val) => {
            if (typeof val !== 'string' || !val.length) {
              throw new errors.InvalidClientMetadata(
                isAry ? `${prop} must only contain strings` : `${prop} must be a string`);
            }
          });
        }
      });
    }

    webUris() {
      WEB_URI.forEach((prop) => {
        if (this[prop] !== undefined) {
          const isAry = ARYS.indexOf(prop) !== -1;
          (isAry ? this[prop] : [this[prop]]).forEach((val) => {
            if (!validUrl.isWebUri(val)) {
              throw new errors.InvalidClientMetadata(
                isAry ? `${prop} must only contain web uris` : `${prop} must be a web uri`);
            }
          });
        }
      });
    }

    arrays() {
      ARYS.forEach((prop) => {
        if (this[prop] !== undefined) {
          if (!Array.isArray(this[prop])) {
            throw new errors.InvalidClientMetadata(`${prop} must be an array`);
          }
          this[prop] = _.uniq(this[prop]);
        }
      });
    }

    lengths() {
      LENGTH.forEach((prop) => {
        if (this[prop] !== undefined && !this[prop].length) {
          throw new errors.InvalidClientMetadata(`${prop} must contain members`);
        }
      });
    }

    booleans() {
      BOOL.forEach((prop) => {
        if (this[prop] !== undefined) {
          if (typeof this[prop] !== 'boolean') {
            throw new errors.InvalidClientMetadata(`${prop} must be a boolean`);
          }
        }
      });
    }

    whens() {
      _.forEach(WHEN, (then, when) => {
        if (this[when] !== undefined && this[then[0]] === undefined) {
          throw new errors.InvalidClientMetadata(`${then[0]} is mandatory property`);
        } else if (this[when] === undefined && this[then[0]] !== undefined) {
          this[when] = then[1];
        }
      });
    }

    enums() {
      _.forEach(ENUM, (only, prop) => {
        if (typeof only === 'function') {
          only = only(this); // eslint-disable-line no-param-reassign
        }

        if (this[prop] !== undefined) {
          const isAry = ARYS.indexOf(prop) !== -1;
          if (isAry && this[prop].some((val) => only.indexOf(val) === -1)) {
            throw new errors.InvalidClientMetadata(`${prop} can only contain members [${only}]`);
          } else if (!isAry && only.indexOf(this[prop]) === -1) {
            throw new errors.InvalidClientMetadata(`${prop} must be one of [${only}]`);
          }
        }
      });
    }

    redirectUris() {
      this.redirect_uris.forEach((redirectUri) => {
        if (redirectUri.indexOf('#') !== -1) {
          throw new errors.InvalidClientMetadata('redirect_uris must not contain fragments');
        }

        if (this.application_type === 'web') {
          if (!validUrl.isWebUri(redirectUri)) {
            throw new errors.InvalidClientMetadata('redirect_uris must be a valid web uri');
          }
          if (url.parse(redirectUri).hostname === 'localhost') {
            throw new errors.InvalidClientMetadata(
              'redirect_uris for web clients must not be using localhost');
          }
        }

        if (this.application_type === 'native') {
          if (!validUrl.isUri(redirectUri)) {
            throw new errors.InvalidClientMetadata('redirect_uris must be a valid uri');
          }
          if (url.parse(redirectUri).hostname !== 'localhost') {
            throw new errors.InvalidClientMetadata(
              'redirect_uris for native clients must be using localhost as hostname');
          }
        }
      });
    }
  }

  function schemaValidate(metadata) {
    try {
      const schema = new Schema(metadata);
      return Promise.resolve(schema);
    } catch (err) {
      return Promise.reject(err);
    }
  }

  function sectorValidate(metadata) {
    if (metadata.sector_identifier_uri !== undefined) {
      return got(metadata.sector_identifier_uri, {
        headers: {
          'User-Agent': provider.userAgent(),
        },
        timeout: provider.configuration('timeouts.sector_identifier_uri'),
        retries: 0,
        followRedirect: false,
      }).then(res => {
        try {
          assert.ok(res.statusCode === 200,
            `unexpected sector_identifier_uri statusCode, expected 200, got ${res.statusCode}`);
          const body = JSON.parse(res.body);
          assert(Array.isArray(body),
            'sector_identifier_uri must return single JSON array');
          const missing = metadata.redirect_uris.find((uri) => body.indexOf(uri) === -1);
          assert(!missing,
            'all registered redirect_uris must be included in the sector_identifier_uri');
        } catch (err) {
          throw new errors.InvalidClientMetadata(err.message);
        }

        return metadata;
      }, (error) => {
        throw new errors.InvalidClientMetadata(
          `could not load sector_identifier_uri (${error.message})`);
      });
    }

    return metadata;
  }

  function buildClient(metadata) {
    const client = new Client(); // eslint-disable-line no-use-before-define

    Object.defineProperty(client, 'sectorIdentifier', {
      enumerable: false,
      writable: true,
    });

    Object.assign(client, _.mapKeys(metadata, (value, key) => _.camelCase(key)));

    return client;
  }

  function buildKeyStore(client) {
    Object.defineProperty(client, 'keystore', { value: jose.JWK.createKeyStore() });
    client.keystore.jwksUri = client.jwksUri;

    client.keystore.refresh = function refreshKeyStore() {
      if (!this.jwksUri) {
        return Promise.resolve();
      }

      return got(this.jwksUri, {
        headers: {
          'User-Agent': provider.userAgent(),
        },
        timeout: provider.configuration('timeouts.jwks_uri'),
        retries: 0,
        followRedirect: false,
      }).then((response) => {
        assert.ok(response.statusCode === 200,
          `unexpected jwks_uri statusCode, expected 200, got ${response.statusCode}`);

        const body = JSON.parse(response.body);

        if (!Array.isArray(body.keys)) {
          throw new Error('invalid jwks_uri response');
        }

        const promises = [];
        const kids = _.map(body.keys, 'kid');

        body.keys.forEach((key) => {
          if (KEY_TYPES.indexOf(key.kty) !== -1 && !this.get(key.kid)) {
            promises.push(this.add(_.pick(key, KEY_ATTRIBUTES)));
          }
        });

        this.all().forEach((key) => {
          if (KEY_TYPES.indexOf(key.kty) !== -1 && kids.indexOf(key.kid) === -1) {
            promises.push(this.remove(key));
          }
        });

        return Promise.all(promises);
      }).catch((err) => {
        throw new Error(`jwks_uri could not be refreshed (${err.message})`);
      });
    };

    const promises = [];

    if (client.jwks && client.jwks.keys) {
      client.jwks.keys.forEach((key) => {
        if (KEY_TYPES.indexOf(key.kty) !== -1) {
          promises.push(client.keystore.add(_.pick(key, KEY_ATTRIBUTES)));
        }
      });
    }

    promises.push(client.keystore.refresh());

    // TODO: DRY the adding of keys;

    return Promise.all(promises).then(() => {
      client.keystore.add({
        k: base64url(new Buffer(client.clientSecret)),
        kid: 'clientSecret',
        kty: 'oct',
      });
    })
    .then(() => client);
  }

  function register(client) {
    client.constructor.clients = client.constructor.clients || /* istanbul ignore next */ {};
    client.constructor.clients[client.clientId] = client;

    return client;
  }

  class Client {

    static get adapter() {
      const Adapter = provider.configuration('adapter');
      if (!this._adapter) {
        this._adapter = new Adapter(this.name);
      }
      return this._adapter;
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

    static add(metadata) {
      return schemaValidate(metadata)
        .then(sectorValidate)
        .then(buildClient)
        .then(buildKeyStore)
        .then(register);
    }

    static remove(id) {
      this.clients = this.clients || /* istanbul ignore next */ {};
      delete this.clients[id];
    }

    static find(id) {
      this.clients = this.clients || /* istanbul ignore next */ {};

      if (this.clients[id]) {
        return Promise.resolve(this.clients[id]);
      }

      return this.adapter.find(id).then((properties) => {
        if (properties) {
          return this.add(properties);
        }
        return undefined;
      });
    }

  }

  return Client;
};
