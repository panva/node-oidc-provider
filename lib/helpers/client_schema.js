'use strict';

const _ = require('lodash');
const errors = require('./errors');
const url = require('url');
const validUrl = require('valid-url');

const RECOGNIZED_METADATA = [
  'application_type',
  'backchannel_logout_uri',
  'backchannel_logout_session_required',
  'client_id',
  'client_id_issued_at',
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

const REQUIRED = [
  'client_id',
  // 'client_secret', => validated elsewhere and only needed somewhen
  'redirect_uris',
];

const BOOL = [
  'require_auth_time',
  'backchannel_logout_session_required',
];

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
  'backchannel_logout_uri',
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
  request_object_encryption_enc: ['request_object_encryption_alg', 'A128CBC-HS256'],
};

const WEB_URI = [
  'client_uri',
  'initiate_login_uri',
  'jwks_uri',
  'logo_uri',
  'policy_uri',
  'tos_uri',
  'sector_identifier_uri',
  'backchannel_logout_uri',

  // in arrays
  'post_logout_redirect_uris',
  'request_uris',
];

const LENGTH = [
  'grant_types',
  'redirect_uris',
  'response_types',
];

module.exports = function getSchema(provider) {
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

  const DEFAULT = {
    application_type: 'web',
    backchannel_logout_session_required: provider.configuration('features.backchannelLogout') ?
      false : undefined,
    grant_types: ['authorization_code'],
    id_token_signed_response_alg: 'RS256',
    post_logout_redirect_uris: provider.configuration('features.sessionManagement') ?
      [] : undefined,
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
      Object.assign(this, _.chain(metadata)
        .omitBy(_.isNull)
        .pick(RECOGNIZED_METADATA)
        .value());

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

      const rts = _.chain(this.response_types)
        .map(rt => rt.split(' '))
        .flatten()
        .uniq()
        .value();

      if (this.token_endpoint_auth_method === 'none') {
        if (_.includes(this.grant_types, 'authorization_code')) {
          throw new errors.InvalidClientMetadata(
            'grant_types must not use token endpoint when token_endpoint_auth_method is none');
        }
      }

      if (_.includes(rts, 'code') && !_.includes(this.grant_types, 'authorization_code')) {
        throw new errors.InvalidClientMetadata(
          'grant_types must contain authorization_code when code is amongst response_types');
      }

      if (_.includes(rts, 'token') || _.includes(rts, 'id_token')) {
        if (!_.includes(this.grant_types, 'implicit')) {
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

      const validateSecretPresence = validateSecretLength ||
        ['private_key_jwt', 'none'].indexOf(this.token_endpoint_auth_method) === -1;

      if (validateSecretPresence && !this.client_secret) {
        throw new errors.InvalidClientMetadata('client_secret is mandatory property');
      }

      if (validateSecretLength) {
        if (this.client_secret.length < validateSecretLength) {
          throw new errors.InvalidClientMetadata('insufficient client_secret length');
        }
      }

        // PAIRWISE PRESENCE
      if (this.subject_type === 'pairwise' && !this.sector_identifier_uri) {
        const hosts = _.chain(this.redirect_uris)
          .map(uri => url.parse(uri).host)
          .uniq()
          .value();

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

      if (this.jwks !== undefined && this.jwks_uri !== undefined) {
        throw new errors.InvalidClientMetadata(
          'jwks and jwks_uri must not be used at the same time');
      }

      if (this.jwks !== undefined) {
        if (!Array.isArray(this.jwks.keys)) {
          throw new errors.InvalidClientMetadata('jwks must be a JWK Set');
        }
        if (!this.jwks.keys.length) {
          throw new errors.InvalidClientMetadata('jwks.keys must not be empty');
        }
      }
    }

    required() {
      REQUIRED.forEach((prop) => {
        if (!this[prop]) {
          throw new errors.InvalidClientMetadata(`${prop} is mandatory property`);
        }
      });

      const requireJwks = this.token_endpoint_auth_method === 'private_key_jwt' ||
        (String(this.request_object_signing_alg).match(/^(RS|ES)/)) ||
        (String(this.id_token_encrypted_response_alg).match(/^(RSA|ECDH)/)) ||
        (String(this.userinfo_encrypted_response_alg).match(/^(RSA|ECDH)/));

      if (requireJwks && !this.jwks && !this.jwks_uri) {
        throw new errors.InvalidClientMetadata('jwks or jwks_uri is mandatory for this client');
      }
    }

    strings() {
      STRING.forEach((prop) => {
        if (this[prop] !== undefined) {
          const isAry = ARYS.indexOf(prop) !== -1;
          (isAry ? this[prop] : [this[prop]]).forEach((val) => {
            if (typeof val !== 'string' || !val.length) {
              throw new errors.InvalidClientMetadata(
                isAry ? `${prop} must only contain strings` :
                  `${prop} must be a non-empty string if provided`);
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
      if (LENGTH.every(prop => this[prop] && this[prop].length === 0)) {
        return;
      }
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
          if (isAry && this[prop].some((val) => {
            if (only instanceof Set) {
              return !only.has(val);
            }
            return only.indexOf(val) === -1;
          })) {
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

  return Schema;
};
