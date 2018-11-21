const { URL } = require('url');

const _ = require('lodash');

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

const validUrl = require('./valid_url');
const { InvalidClientMetadata } = require('./errors');
const sectorIdentifier = require('./sector_identifier');
const instance = require('./weak_cache');

const clientAuthEndpoints = ['token', 'introspection', 'revocation'];
const W3CEmailRegExp = /^[a-zA-Z0-9.!#$%&’*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/;

function invalidate(message) {
  throw new InvalidClientMetadata(message);
}

function checkClientAuth(schema) {
  return !!clientAuthEndpoints.find(endpoint => ['private_key_jwt', 'self_signed_tls_client_auth'].includes(schema[`${endpoint}_endpoint_auth_method`]));
}

module.exports = function getSchema(provider) {
  const configuration = instance(provider).configuration();
  const { features } = configuration;

  const RECOGNIZED_METADATA = _.clone(RECOGNIZED);
  const DEFAULT = _.clone(DEFAULTS);

  if (configuration.subjectTypes.length === 1 && configuration.subjectTypes.includes('pairwise')) {
    DEFAULT.subject_type = 'pairwise';
  }

  const tlsClientAuthEnabled = ['token', 'revocation', 'introspection']
    .find(endpoint => configuration[`${endpoint}EndpointAuthMethods`].includes('tls_client_auth'));

  if (tlsClientAuthEnabled) {
    RECOGNIZED_METADATA.push('tls_client_auth_subject_dn');
  }

  if (configuration.tokenEndpointAuthSigningAlgValues) {
    RECOGNIZED_METADATA.push('token_endpoint_auth_signing_alg');
  }

  if (features.introspection) {
    RECOGNIZED_METADATA.push('introspection_endpoint_auth_method');
    if (configuration.introspectionEndpointAuthSigningAlgValues) {
      RECOGNIZED_METADATA.push('introspection_endpoint_auth_signing_alg');
    }

    if (features.jwtIntrospection) {
      RECOGNIZED_METADATA.push('introspection_signed_response_alg');

      if (features.encryption) {
        RECOGNIZED_METADATA.push('introspection_encrypted_response_alg');
        RECOGNIZED_METADATA.push('introspection_encrypted_response_enc');
      }
    }
  }

  if (features.revocation) {
    RECOGNIZED_METADATA.push('revocation_endpoint_auth_method');
    if (configuration.revocationEndpointAuthSigningAlgValues) {
      RECOGNIZED_METADATA.push('revocation_endpoint_auth_signing_alg');
    }
  }

  if (features.sessionManagement || features.backchannelLogout || features.frontchannelLogout) {
    RECOGNIZED_METADATA.push('post_logout_redirect_uris');
  }

  if (features.backchannelLogout) {
    RECOGNIZED_METADATA.push('backchannel_logout_session_required');
    RECOGNIZED_METADATA.push('backchannel_logout_uri');
  }

  if (features.frontchannelLogout) {
    RECOGNIZED_METADATA.push('frontchannel_logout_session_required');
    RECOGNIZED_METADATA.push('frontchannel_logout_uri');
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

  if (features.jwtResponseModes) {
    RECOGNIZED_METADATA.push('authorization_signed_response_alg');
    if (features.encryption) {
      RECOGNIZED_METADATA.push('authorization_encrypted_response_alg');
      RECOGNIZED_METADATA.push('authorization_encrypted_response_enc');
    }
  }

  if (features.webMessageResponseMode) {
    RECOGNIZED_METADATA.push('web_message_uris');
    DEFAULT.web_message_uris = [];
  }

  if (features.certificateBoundAccessTokens) {
    RECOGNIZED_METADATA.push('tls_client_certificate_bound_access_tokens');
    DEFAULT.tls_client_certificate_bound_access_tokens = false;
  }

  instance(provider).RECOGNIZED_METADATA = RECOGNIZED_METADATA;

  const ENUM = {
    ...ENUMS,
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
    request_object_signing_alg: () => configuration.requestObjectSigningAlgValues,
    request_object_encryption_alg: () => configuration.requestObjectEncryptionAlgValues,
    request_object_encryption_enc: () => configuration.requestObjectEncryptionEncValues,
    response_types: () => configuration.responseTypes,
    subject_type: () => configuration.subjectTypes,
    token_endpoint_auth_method: () => configuration.tokenEndpointAuthMethods,
    token_endpoint_auth_signing_alg: () => configuration.tokenEndpointAuthSigningAlgValues,
    userinfo_encrypted_response_alg: () => configuration.userinfoEncryptionAlgValues,
    userinfo_encrypted_response_enc: () => configuration.userinfoEncryptionEncValues,
    userinfo_signed_response_alg: () => configuration.userinfoSigningAlgValues,
    introspection_encrypted_response_alg: () => configuration.introspectionEncryptionAlgValues,
    introspection_encrypted_response_enc: () => configuration.introspectionEncryptionEncValues,
    introspection_signed_response_alg: () => configuration.introspectionSigningAlgValues,
    authorization_encrypted_response_alg: () => configuration.authorizationEncryptionAlgValues,
    authorization_encrypted_response_enc: () => configuration.authorizationEncryptionEncValues,
    authorization_signed_response_alg: () => configuration.authorizationSigningAlgValues,

    // must be after token_* specific
    introspection_endpoint_auth_method: () => configuration.introspectionEndpointAuthMethods,
    introspection_endpoint_auth_signing_alg:
      () => configuration.introspectionEndpointAuthSigningAlgValues,
    revocation_endpoint_auth_method: () => configuration.revocationEndpointAuthMethods,
    revocation_endpoint_auth_signing_alg:
      () => configuration.revocationEndpointAuthSigningAlgValues,
  };

  const requestSignAlgRequiringJwks = /^(RS|ES)/;
  const encAlgRequiringJwks = /^(RSA|ECDH)/;

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
        _.pick(DEFAULT, ...RECOGNIZED_METADATA),
        _.pick(metadata, ...RECOGNIZED_METADATA, ...configuration.extraClientMetadata.properties),
      );

      this.required();
      this.booleans();
      this.whens();
      this.arrays();
      this.strings();
      this.normalizeResponseTypes();
      this.enums();
      this.webUris();
      this.postLogoutRedirectUris();
      this.redirectUris();
      this.webMessageUris();
      this.normalizeNativeAppUris();
      this.checkContacts();

      // MAX AGE FORMAT
      if (this.default_max_age !== undefined) {
        if (!Number.isSafeInteger(this.default_max_age) || this.default_max_age <= 0) {
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
      const hsLengths = SECRET_LENGTH_REQUIRED.reduce((lengths, prop) => {
        if (this[prop] && this[prop].startsWith('HS')) {
          lengths.add(parseInt(this[prop].slice(-3), 10));
        }

        return lengths;
      }, new Set());

      clientAuthEndpoints.forEach((endpoint) => {
        switch (this[`${endpoint}_endpoint_auth_method`]) {
          case 'client_secret_jwt':
            if (this[`${endpoint}_endpoint_auth_signing_alg`] === undefined) {
              const required = Math.max(...configuration[`${endpoint}EndpointAuthSigningAlgValues`]
                .filter(alg => alg.startsWith('HS')).map(alg => parseInt(alg.slice(-3), 10)));

              hsLengths.add(required);
            }
            break;

          case 'tls_client_auth':
            if (!this.tls_client_auth_subject_dn) {
              invalidate('tls_client_auth_subject_dn must be provided for tls_client_auth');
            }
            break;

          default:
        }
      });

      const required = _.max(Array.from(hsLengths));

      if (required) {
        const actual = this.client_secret.length * 8;
        if (actual < required) {
          invalidate(`insufficient client_secret length (need at least ${required} bits, got ${actual})`);
        }
      }

      if (this.sector_identifier_uri !== undefined && this.subject_type !== 'pairwise') {
        this.sector_identifier_uri = undefined;
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

      const requireJwks = checkClientAuth(this)
        || (requestSignAlgRequiringJwks.test(this.request_object_signing_alg))
        || (encAlgRequiringJwks.test(this.id_token_encrypted_response_alg))
        || (encAlgRequiringJwks.test(this.userinfo_encrypted_response_alg))
        || (encAlgRequiringJwks.test(this.introspection_encrypted_response_alg))
        || (encAlgRequiringJwks.test(this.authorization_encrypted_response_alg));

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
              invalidate(isAry
                ? `${prop} must only contain strings`
                : `${prop} must be a non-empty string if provided`);
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
              invalidate(isAry
                ? `${prop} must only contain ${type} uris`
                : `${prop} must be a ${type} uri`);
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
      Object.entries(WHEN).forEach(([when, [property, value]]) => {
        if (this[when] !== undefined && this[property] === undefined) {
          invalidate(`${property} is mandatory property when ${when} is provided`);
        } else if (this[when] === undefined && this[property] !== undefined) {
          this[when] = value;
        }
      });
    }

    enums() {
      Object.entries(ENUM).forEach(([prop, fn]) => {
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

    normalizeResponseTypes() {
      this.response_types = this.response_types.map(type => Array.from(new Set(type.split(' '))).sort().join(' '));
    }

    normalizeNativeAppUris() {
      if (this.application_type === 'web') return;
      if (!features.oauthNativeApps) return;

      this.redirect_uris = this.redirect_uris.map((redirectUri) => {
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

    webMessageUris() {
      if (!this.web_message_uris) return;
      this.web_message_uris.forEach((uri) => {
        let origin;
        let protocol;

        try {
          ({ origin, protocol } = new URL(uri));
        } catch (err) {
          invalidate('web_message_uris must only contain valid uris');
        }
        if (!['https:', 'http:'].includes(protocol)) {
          invalidate('web_message_uris must only contain web uris');
        }
        if (origin !== uri) {
          invalidate('web_message_uris must only contain origins');
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
              invalidate('redirect_uris must only contain web uris');
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

    checkContacts() {
      if (this.contacts) {
        this.contacts.forEach((contact) => {
          if (!W3CEmailRegExp.test(contact)) {
            invalidate('contacts can only contain email addresses');
          }
        });
      }
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
