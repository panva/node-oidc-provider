const _ = require('lodash');
const { URL } = require('url');
const validUrl = require('./valid_url');
const { InvalidClientMetadata } = require('./errors');
const sectorIdentifier = require('./sector_identifier');

const instance = require('./weak_cache');

function invalidate(message) {
  throw new InvalidClientMetadata(message);
}

const {
  CLIENT_ATTRIBUTES: {
    ARYS,
    BOOL,
    DEFAULT: DEFAULTS,
    ENUM: ENUMS,
    HTTPS_URI,
    LOOPBACKS,
    RECOGNIZED_METADATA: RECOGNIZED,
    REQUIRED,
    SECRET_LENGTH_REQUIRED,
    STRING,
    WEB_URI,
    WHEN,
  },
} = require('../consts');

module.exports = function getSchema(provider) {
  const configuration = instance(provider).configuration();
  const { features } = configuration;

  const RECOGNIZED_METADATA = _.clone(RECOGNIZED);
  const DEFAULT = _.clone(DEFAULTS);

  if (configuration.subjectTypes.length === 1 && configuration.subjectTypes.includes('pairwise')) {
    DEFAULT.subject_type = 'pairwise';
  }

  if (features.introspection) {
    RECOGNIZED_METADATA.push('introspection_endpoint_auth_method');
    RECOGNIZED_METADATA.push('introspection_endpoint_auth_signing_alg');
  }

  if (features.revocation) {
    RECOGNIZED_METADATA.push('revocation_endpoint_auth_method');
    RECOGNIZED_METADATA.push('revocation_endpoint_auth_signing_alg');
  }

  if (features.sessionManagement) {
    RECOGNIZED_METADATA.push('post_logout_redirect_uris');

    DEFAULT.post_logout_redirect_uris = [];
  }

  if (features.backchannelLogout) {
    RECOGNIZED_METADATA.push('backchannel_logout_session_required');
    RECOGNIZED_METADATA.push('backchannel_logout_uri');

    DEFAULT.backchannel_logout_session_required = false;
  }

  if (features.frontchannelLogout) {
    RECOGNIZED_METADATA.push('frontchannel_logout_session_required');
    RECOGNIZED_METADATA.push('frontchannel_logout_uri');

    DEFAULT.frontchannel_logout_session_required = false;
  }

  if (features.request || features.requestUri) {
    RECOGNIZED_METADATA.push('request_object_signing_alg');
    if (features.encryption) {
      RECOGNIZED_METADATA.push('request_object_encryption_alg');
      RECOGNIZED_METADATA.push('request_object_encryption_enc');
    }
  }

  if (features.requestUri) {
    RECOGNIZED_METADATA.push('request_uris');

    if (features.requestUri.requireRequestUriRegistration) {
      DEFAULT.request_uris = [];
    }
  }

  if (features.encryption) {
    RECOGNIZED_METADATA.push('id_token_encrypted_response_alg');
    RECOGNIZED_METADATA.push('id_token_encrypted_response_enc');
    RECOGNIZED_METADATA.push('userinfo_encrypted_response_alg');
    RECOGNIZED_METADATA.push('userinfo_encrypted_response_enc');
  }

  const ENUM = Object.assign({}, ENUMS, {
    default_acr_values: () => configuration.acrValues,
    grant_types: () => configuration.grantTypes,
    id_token_encrypted_response_alg: () => configuration.idTokenEncryptionAlgValues,
    id_token_encrypted_response_enc: () => configuration.idTokenEncryptionEncValues,
    id_token_signed_response_alg: (metadata) => {
      if (!metadata.response_types.join(' ').includes('id_token')) {
        return configuration.idTokenSigningAlgValues;
      }
      return _.without(configuration.idTokenSigningAlgValues, 'none');
    },
    request_object_encryption_alg: () => configuration.requestObjectEncryptionAlgValues,
    request_object_encryption_enc: () => configuration.requestObjectEncryptionEncValues,
    response_types: () => configuration.responseTypes,
    subject_type: () => configuration.subjectTypes,
    token_endpoint_auth_method: () => configuration.tokenEndpointAuthMethods,
    token_endpoint_auth_signing_alg: () => configuration.tokenEndpointAuthSigningAlgValues,
    userinfo_encrypted_response_alg: () => configuration.userinfoEncryptionAlgValues,
    userinfo_encrypted_response_enc: () => configuration.userinfoEncryptionEncValues,
    userinfo_signed_response_alg: () => configuration.userinfoSigningAlgValues,

    // must be after token_* specific
    introspection_endpoint_auth_method: () => configuration.introspectionEndpointAuthMethods,
    introspection_endpoint_auth_signing_alg: () =>
      configuration.introspectionEndpointAuthSigningAlgValues,
    revocation_endpoint_auth_method: () => configuration.revocationEndpointAuthMethods,
    revocation_endpoint_auth_signing_alg: () =>
      configuration.revocationEndpointAuthSigningAlgValues,
  });

  class Schema {
    constructor(metadata) {
      // unless explicitly provided use token_* values
      ['revocation', 'introspection'].forEach((endpoint) => {
        if (metadata[`${endpoint}_endpoint_auth_method`] === undefined) {
          Object.assign(metadata, {
            [`${endpoint}_endpoint_auth_method`]: metadata.token_endpoint_auth_method || 'client_secret_basic',
          });
        }
        if (metadata[`${endpoint}_endpoint_auth_signing_alg`] === undefined && metadata.token_endpoint_auth_signing_alg) {
          Object.assign(metadata, {
            [`${endpoint}_endpoint_auth_signing_alg`]: metadata.token_endpoint_auth_signing_alg,
          });
        }
      });

      Object.assign(
        this,
        DEFAULT,
        _.pick(metadata, ...RECOGNIZED_METADATA, ...configuration.extraClientMetadata.properties),
      );

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

      const responseTypes = _.chain(this.response_types)
        .map(rt => rt.split(' '))
        .flatten()
        .uniq()
        .value();

      if (this.grant_types.some(type => ['authorization_code', 'implicit'].includes(type)) && !this.response_types.length) {
        invalidate('response_types must contain members');
      }

      if (responseTypes.length && !this.redirect_uris.length) {
        invalidate('redirect_uris must contain members');
      }

      if (responseTypes.includes('code') && !this.grant_types.includes('authorization_code')) {
        invalidate('grant_types must contain authorization_code when code is amongst response_types');
      }

      if (responseTypes.includes('token') || responseTypes.includes('id_token')) {
        if (!this.grant_types.includes('implicit')) {
          invalidate('grant_types must contain implicit when id_token or token are amongst response_types');
        }
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

      // SECTOR IDENTIFIER VALIDATION
      sectorIdentifier({
        subjectType: this.subject_type,
        sectorIdentifierUri: this.sector_identifier_uri,
        redirectUris: this.redirect_uris,
      });

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

      this.processCustomMetadata();
      this.ensureStripUnrecognized();
    }

    required() {
      let checked = REQUIRED;
      if (provider.Client.needsSecret(this)) checked = checked.concat('client_secret');

      checked.forEach((prop) => {
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
          this[when] = then[1]; // eslint-disable-line prefer-destructuring
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
      if (!features.oauthNativeApps) return;

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
        let hostname;
        let protocol;
        let hash;

        try {
          ({ hash, hostname, protocol } = new URL(redirectUri));
        } catch (err) {
          invalidate('redirect_uris must only contain valid uris');
        }

        if (hash) {
          invalidate('redirect_uris must not contain fragments');
        }

        switch (this.application_type) { // eslint-disable-line default-case
          case 'web': {
            if (!['https:', 'http:'].includes(protocol)) {
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
            if (features.oauthNativeApps) {
              switch (protocol) {
                case 'http:': // Loopback Interface Redirection
                  if (!LOOPBACKS.includes(hostname)) {
                    invalidate('redirect_uris for native clients using http as a protocol can only use loopback addresses as hostnames');
                  }
                  break;
                case 'https:': // Claimed HTTPS URI Redirection
                  if (LOOPBACKS.includes(hostname)) {
                    invalidate(`redirect_uris for native clients using claimed HTTPS URIs must not be using ${hostname} as hostname`);
                  }
                  break;
                default: // Private-use URI Scheme Redirection
                  if (!protocol.includes('.')) {
                    invalidate('redirect_uris for native clients using Custom URI scheme should use reverse domain name based scheme');
                  }
              }
            } else {
              if (protocol === 'https:') {
                invalidate('redirect_uris for native clients must not be using https URI scheme');
              }

              if (protocol === 'http:' && hostname !== 'localhost') {
                invalidate('redirect_uris for native clients must be using localhost as hostname');
              }
            }
            break;
          }
        }
      });
    }

    processCustomMetadata() {
      configuration.extraClientMetadata.properties.forEach((prop) => {
        configuration.extraClientMetadata.validator(prop, this[prop], this);
      });
    }

    ensureStripUnrecognized() {
      const whitelisted = [...RECOGNIZED_METADATA, ...configuration.extraClientMetadata.properties];
      Object.keys(this).forEach((prop) => {
        if (!whitelisted.includes(prop)) {
          _.unset(this, prop);
        }
      });
    }
  }

  return Schema;
};
