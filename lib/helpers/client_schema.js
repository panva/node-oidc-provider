const _ = require('lodash');
const assert = require('assert');
const { URL } = require('url');
const validUrl = require('./valid_url');
const { InvalidClientMetadata } = require('./errors');

const instance = require('./weak_cache');

function invalidate(message) {
  throw new InvalidClientMetadata(message);
}

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
  'introspection_endpoint_auth_method',
  'introspection_endpoint_auth_signing_alg',
  'revocation_endpoint_auth_method',
  'revocation_endpoint_auth_signing_alg',
  'tos_uri',
  'userinfo_encrypted_response_alg',
  'userinfo_encrypted_response_enc',
  'userinfo_signed_response_alg',
];

const SECRET_LENGTH_REQUIRED = [
  'id_token_signed_response_alg',
  'request_object_signing_alg',
  'token_endpoint_auth_signing_alg',
  'revocation_endpoint_auth_signing_alg',
  'introspection_endpoint_auth_signing_alg',
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
  'introspection_endpoint_auth_method',
  'revocation_endpoint_auth_method',
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
  'request_uris',
];

const HTTPS_URI = [
  'initiate_login_uri',
  'sector_identifier_uri',
  'request_uris',
];

const LOOPBACKS = ['localhost', '127.0.0.1', '[::1]'];

module.exports = function getSchema(provider) {
  const ENUM = {
    application_type: () => ['native', 'web'],
    response_types: () => instance(provider).configuration('responseTypes'),
    default_acr_values: () => instance(provider).configuration('acrValues'),
    grant_types: () => instance(provider).configuration('grantTypes'),
    subject_type: () => instance(provider).configuration('subjectTypes'),
    token_endpoint_auth_method: () => instance(provider).configuration('tokenEndpointAuthMethods'),
    token_endpoint_auth_signing_alg: () => instance(provider).configuration('tokenEndpointAuthSigningAlgValues'),
    introspection_endpoint_auth_method: () => instance(provider).configuration('introspectionEndpointAuthMethods'),
    introspection_endpoint_auth_signing_alg: () => instance(provider).configuration('introspectionEndpointAuthSigningAlgValues'),
    revocation_endpoint_auth_method: () => instance(provider).configuration('revocationEndpointAuthMethods'),
    revocation_endpoint_auth_signing_alg: () => instance(provider).configuration('revocationEndpointAuthSigningAlgValues'),
    userinfo_signed_response_alg: () => instance(provider).configuration('userinfoSigningAlgValues'),
    id_token_signed_response_alg: (metadata) => {
      if (!metadata.response_types.join(' ').includes('id_token')) {
        return instance(provider).configuration('idTokenSigningAlgValues');
      }
      return _.without(instance(provider).configuration('idTokenSigningAlgValues'), 'none');
    },
    id_token_encrypted_response_alg: () => instance(provider).configuration('idTokenEncryptionAlgValues'),
    id_token_encrypted_response_enc: () => instance(provider).configuration('idTokenEncryptionEncValues'),
    userinfo_encrypted_response_alg: () => instance(provider).configuration('userinfoEncryptionAlgValues'),
    userinfo_encrypted_response_enc: () => instance(provider).configuration('userinfoEncryptionEncValues'),
    request_object_encryption_alg: () => instance(provider).configuration('requestObjectEncryptionAlgValues'),
    request_object_encryption_enc: () => instance(provider).configuration('requestObjectEncryptionEncValues'),
  };

  const DEFAULT = {
    application_type: 'web',
    backchannel_logout_session_required: instance(provider).configuration('features.backchannelLogout') ?
      false : undefined,
    grant_types: ['authorization_code'],
    id_token_signed_response_alg: 'RS256',
    post_logout_redirect_uris: instance(provider).configuration('features.sessionManagement') ?
      [] : undefined,
    request_uris: instance(provider).configuration('features.requestUri.requireRequestUriRegistration') ?
      [] : undefined,
    require_auth_time: false,
    response_types: ['code'],
    subject_type: 'public',
    token_endpoint_auth_method: 'client_secret_basic',
  };

  class Schema {
    constructor(metadata) {
      Object.assign(this, DEFAULT, _.chain(metadata)
        .omitBy(_.isNull)
        .pick(RECOGNIZED_METADATA)
        .value());

      ['revocation', 'introspection'].forEach((endpoint) => {
        if (this[`${endpoint}_endpoint_auth_method`] === undefined) {
          this[`${endpoint}_endpoint_auth_method`] = this.token_endpoint_auth_method || 'client_secret_basic';
        }
        if (this[`${endpoint}_endpoint_auth_signing_alg`] === undefined) {
          this[`${endpoint}_endpoint_auth_signing_alg`] = this.token_endpoint_auth_signing_alg;
        }
      });

      this.required();
      this.whens();
      this.arrays();
      this.strings();
      this.enums();
      this.booleans();
      this.webUris();
      this.postLogoutRedirectUris();
      this.redirectUris();
      this.normalizeNativeAppUris();

      // MAX AGE FORMAT
      if (this.default_max_age !== undefined) {
        if (!Number.isInteger(this.default_max_age) || this.default_max_age <= 0) {
          invalidate('default_max_age must be a positive integer');
        }
      }

      const rts = _.chain(this.response_types)
        .map(rt => rt.split(' '))
        .flatten()
        .uniq()
        .value();

      if (this.grant_types.some(type => ['authorization_code', 'implicit'].includes(type)) && !this.response_types.length) {
        invalidate('response_types must contain members');
      }

      if (rts.length && !this.redirect_uris.length) {
        invalidate('redirect_uris must contain members');
      }

      if (rts.includes('code') && !this.grant_types.includes('authorization_code')) {
        invalidate('grant_types must contain authorization_code when code is amongst response_types');
      }

      if (rts.includes('token') || rts.includes('id_token')) {
        if (!this.grant_types.includes('implicit')) {
          invalidate('grant_types must contain implicit when id_token or token are amongst response_types');
        }
      }

      if (instance(provider).Client.needsSecret(this) && !this.client_secret) {
        invalidate('client_secret is mandatory property');
      }

      // CLIENT SECRET LENGTH
      const hsLengths = SECRET_LENGTH_REQUIRED.map((prop) => {
        if (this[prop] && this[prop].startsWith('HS')) {
          return parseInt(this[prop].slice(-3) / 8, 10);
        }

        return undefined;
      });

      const validateSecretLength = _.max(hsLengths);

      if (validateSecretLength) {
        if (this.client_secret.length < validateSecretLength) {
          invalidate('insufficient client_secret length');
        }
      }

      // PAIRWISE PRESENCE
      if (this.subject_type === 'pairwise' && !this.sector_identifier_uri) {
        const hosts = _.chain(this.redirect_uris)
          .map(uri => new URL(uri).host)
          .uniq()
          .value();

        if (hosts.length === 1) {
          this.sector_identifier = hosts[0];
        } else {
          invalidate('sector_identifier_uri is required when using multiple hosts in your redirect_uris');
        }
      } else if (this.sector_identifier_uri) {
        this.sector_identifier = new URL(this.sector_identifier_uri).host;
      }

      if (this.jwks !== undefined && this.jwks_uri !== undefined) {
        invalidate('jwks and jwks_uri must not be used at the same time');
      }

      if (this.jwks !== undefined) {
        if (!Array.isArray(this.jwks.keys)) {
          invalidate('jwks must be a JWK Set');
        }
        if (!this.jwks.keys.length) {
          invalidate('jwks.keys must not be empty');
        }
      }
    }

    required() {
      REQUIRED.forEach((prop) => {
        if (!this[prop]) {
          invalidate(`${prop} is mandatory property`);
        }
      });

      const requireJwks = this.token_endpoint_auth_method === 'private_key_jwt' ||
        this.introspection_endpoint_auth_method === 'private_key_jwt' ||
        this.revocation_endpoint_auth_method === 'private_key_jwt' ||
        (String(this.request_object_signing_alg).match(/^(RS|ES)/)) ||
        (String(this.id_token_encrypted_response_alg).match(/^(RSA|ECDH)/)) ||
        (String(this.userinfo_encrypted_response_alg).match(/^(RSA|ECDH)/));

      if (requireJwks && !this.jwks && !this.jwks_uri) {
        invalidate('jwks or jwks_uri is mandatory for this client');
      }
    }

    strings() {
      STRING.forEach((prop) => {
        if (this[prop] !== undefined) {
          const isAry = ARYS.includes(prop);
          (isAry ? this[prop] : [this[prop]]).forEach((val) => {
            if (typeof val !== 'string' || !val.length) {
              invalidate(isAry ?
                `${prop} must only contain strings` :
                `${prop} must be a non-empty string if provided`);
            }
          });
        }
      });
    }

    webUris() {
      WEB_URI.forEach((prop) => {
        if (this[prop] !== undefined) {
          const isAry = ARYS.includes(prop);
          (isAry ? this[prop] : [this[prop]]).forEach((val) => {
            const method = HTTPS_URI.includes(prop) ? 'isHttpsUri' : 'isWebUri';
            const type = method === 'isWebUri' ? 'web' : 'https';
            if (!validUrl[method](val)) {
              invalidate(isAry ?
                `${prop} must only contain ${type} uris` :
                `${prop} must be a ${type} uri`);
            }
          });
        }
      });
    }

    arrays() {
      ARYS.forEach((prop) => {
        if (this[prop] !== undefined) {
          if (!Array.isArray(this[prop])) {
            invalidate(`${prop} must be an array`);
          }
          this[prop] = _.uniq(this[prop]);
        }
      });
    }

    booleans() {
      BOOL.forEach((prop) => {
        if (this[prop] !== undefined) {
          if (typeof this[prop] !== 'boolean') {
            invalidate(`${prop} must be a boolean`);
          }
        }
      });
    }

    whens() {
      _.forEach(WHEN, (then, when) => {
        if (this[when] !== undefined && this[then[0]] === undefined) {
          invalidate(`${then[0]} is mandatory property`);
        } else if (this[when] === undefined && this[then[0]] !== undefined) {
          this[when] = then[1];
        }
      });
    }

    enums() {
      _.forEach(ENUM, (fn, prop) => {
        const only = fn(this);

        if (this[prop] !== undefined) {
          const isAry = ARYS.includes(prop);
          if (isAry && this[prop].some((val) => {
            if (only instanceof Set) {
              return !only.has(val);
            }
            return !only.includes(val);
          })) {
            invalidate(`${prop} can only contain members [${Array.from(only)}]`);
          } else if (!isAry && !only.includes(this[prop])) {
            invalidate(`${prop} must be one of [${Array.from(only)}]`);
          }
        }
      });
    }

    normalizeNativeAppUris() {
      if (this.application_type === 'web') return;
      if (!instance(provider).configuration('features.oauthNativeApps')) return;

      this.redirect_uris = _.map(this.redirect_uris, (redirectUri) => {
        const parsed = new URL(redirectUri);
        // remove the port component, making dynamic ports allowed for loopback uris
        if (parsed.protocol === 'http:' && LOOPBACKS.includes(parsed.hostname)) {
          parsed.port = 80; // http + 80 = no port part in the string
          return parsed.href;
        }

        return redirectUri;
      });
    }

    postLogoutRedirectUris() {
      if (!this.post_logout_redirect_uris) return;
      this.post_logout_redirect_uris.forEach((uri) => {
        try {
          new URL(uri); // eslint-disable-line no-new
        } catch (err) {
          invalidate('post_logout_redirect_uris must only contain uris');
        }
      });
    }

    redirectUris() {
      this.redirect_uris.forEach((redirectUri) => {
        if (redirectUri.includes('#')) {
          invalidate('redirect_uris must not contain fragments');
        }

        switch (this.application_type) { // eslint-disable-line default-case
          case 'web': {
            let hostname;
            let protocol;
            try {
              const parsed = new URL(redirectUri);
              hostname = parsed.hostname;
              protocol = parsed.protocol;
              assert(['https:', 'http:'].includes(protocol));
            } catch (err) {
              invalidate('redirect_uris must only contain valid web uris');
            }

            if (this.grant_types.includes('implicit') && protocol === 'http:') {
              invalidate('redirect_uris for web clients using implicit flow MUST only register URLs using the https scheme');
            }

            if (this.grant_types.includes('implicit') && hostname === 'localhost') {
              invalidate('redirect_uris for web clients using implicit flow must not be using localhost');
            }
            break;
          }
          case 'native': {
            let parsed;
            try {
              parsed = new URL(redirectUri); // eslint-disable-line no-new
            } catch (err) {
              invalidate('redirect_uris must only contain valid uris');
            }

            if (instance(provider).configuration('features.oauthNativeApps')) {
              switch (parsed.protocol) {
                case 'http:': // Loopback Interface Redirection
                  if (!LOOPBACKS.includes(parsed.hostname)) {
                    invalidate('redirect_uris for native clients using http as a protocol can only use loopback addresses as hostnames');
                  }
                  break;
                case 'https:': // Claimed HTTPS URI Redirection
                  if (LOOPBACKS.includes(parsed.hostname)) {
                    invalidate(`redirect_uris for native clients using claimed HTTPS URIs must not be using ${parsed.hostname} as hostname`);
                  }
                  break;
                default: // Private-use URI Scheme Redirection
                  if (!parsed.protocol.includes('.')) {
                    invalidate('redirect_uris for native clients using Custom URI scheme should use reverse domain name based scheme');
                  }
              }
            } else {
              if (parsed.protocol === 'https:') {
                invalidate('redirect_uris for native clients must not be using https URI scheme');
              }

              if (parsed.protocol === 'http:' && parsed.hostname !== 'localhost') {
                invalidate('redirect_uris for native clients must be using localhost as hostname');
              }
            }
            break;
          }
        }
      });
    }
  }

  return Schema;
};
