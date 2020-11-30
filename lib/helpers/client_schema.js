const url = require('url');

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
    STRING,
    WEB_URI,
    WHEN,
  },
  DYNAMIC_SCOPE_LABEL,
} = require('../consts');

const validUrl = require('./valid_url');
const { InvalidClientMetadata } = require('./errors');
const sectorIdentifier = require('./sector_identifier');
const instance = require('./weak_cache');
const formatters = require('./formatters');
const pick = require('./_/pick');
const without = require('./_/without');
const omitBy = require('./_/omit_by');

const clientAuthEndpoints = ['token', 'introspection', 'revocation'];
// TODO: in v7.x remove the `introspection` and `revocation` metadata, only token endpoint will be
// used
const W3CEmailRegExp = /^[a-zA-Z0-9.!#$%&’*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/;
const encAlgRequiringJwks = /^(RSA|ECDH)/;
const requestSignAlgRequiringJwks = /^(?:PS(?:256|384|512)|RS(?:256|384|512)|ES(?:256K?|384|512)|EdDSA)$/;

function isUndefined(value) {
  return value === undefined;
}

function checkClientAuth(schema) {
  return !!clientAuthEndpoints.find((endpoint) => ['private_key_jwt', 'self_signed_tls_client_auth'].includes(schema[`${endpoint}_endpoint_auth_method`]));
}

module.exports = function getSchema(provider) {
  const configuration = instance(provider).configuration();
  const { features } = configuration;

  const { scopes } = configuration;
  const dynamicScopes = new Set(
    [...configuration.dynamicScopes].map((s) => s[DYNAMIC_SCOPE_LABEL]).filter(Boolean),
  );

  const RECOGNIZED_METADATA = [...RECOGNIZED];
  const DEFAULT = JSON.parse(JSON.stringify(DEFAULTS));
  const DEFAULT_CONFIGURATION = JSON.parse(JSON.stringify(configuration.clientDefaults));
  Object.assign(DEFAULT, DEFAULT_CONFIGURATION);

  if (configuration.subjectTypes.size === 1 && configuration.subjectTypes.has('pairwise')) {
    DEFAULT.subject_type = 'pairwise';
  }

  if (features.mTLS.enabled && features.mTLS.tlsClientAuth) {
    RECOGNIZED_METADATA.push('tls_client_auth_subject_dn');
    RECOGNIZED_METADATA.push('tls_client_auth_san_dns');
    RECOGNIZED_METADATA.push('tls_client_auth_san_uri');
    RECOGNIZED_METADATA.push('tls_client_auth_san_ip');
    RECOGNIZED_METADATA.push('tls_client_auth_san_email');
  }

  if (configuration.tokenEndpointAuthSigningAlgValues) {
    RECOGNIZED_METADATA.push('token_endpoint_auth_signing_alg');
  }

  if (features.jwtUserinfo.enabled) {
    RECOGNIZED_METADATA.push('userinfo_signed_response_alg');
  }

  if (features.introspection.enabled) {
    RECOGNIZED_METADATA.push('introspection_endpoint_auth_method');
    if (configuration.introspectionEndpointAuthSigningAlgValues) {
      RECOGNIZED_METADATA.push('introspection_endpoint_auth_signing_alg');
    }

    if (features.jwtIntrospection.enabled) {
      RECOGNIZED_METADATA.push('introspection_signed_response_alg');

      if (features.encryption.enabled) {
        RECOGNIZED_METADATA.push('introspection_encrypted_response_alg');
        RECOGNIZED_METADATA.push('introspection_encrypted_response_enc');
      }
    }
  }

  if (features.revocation.enabled) {
    RECOGNIZED_METADATA.push('revocation_endpoint_auth_method');
    if (configuration.revocationEndpointAuthSigningAlgValues) {
      RECOGNIZED_METADATA.push('revocation_endpoint_auth_signing_alg');
    }
  }

  if (features.rpInitiatedLogout.enabled) {
    RECOGNIZED_METADATA.push('post_logout_redirect_uris');
  }

  if (features.backchannelLogout.enabled) {
    RECOGNIZED_METADATA.push('backchannel_logout_session_required');
    RECOGNIZED_METADATA.push('backchannel_logout_uri');
  }

  if (features.frontchannelLogout.enabled) {
    RECOGNIZED_METADATA.push('frontchannel_logout_session_required');
    RECOGNIZED_METADATA.push('frontchannel_logout_uri');
  }

  if (features.requestObjects.request || features.requestObjects.requestUri) {
    RECOGNIZED_METADATA.push('request_object_signing_alg');
    RECOGNIZED_METADATA.push('require_signed_request_object');
    if (features.encryption.enabled) {
      RECOGNIZED_METADATA.push('request_object_encryption_alg');
      RECOGNIZED_METADATA.push('request_object_encryption_enc');
    }
  }

  if (features.requestObjects.requestUri) {
    RECOGNIZED_METADATA.push('request_uris');

    if (features.requestObjects.requireUriRegistration) {
      if (!('request_uris' in configuration.clientDefaults)) {
        DEFAULT.request_uris = [];
      }
    }
  }

  if (features.pushedAuthorizationRequests.enabled) {
    RECOGNIZED_METADATA.push('require_pushed_authorization_requests');
  }

  if (features.encryption.enabled) {
    RECOGNIZED_METADATA.push('id_token_encrypted_response_alg');
    RECOGNIZED_METADATA.push('id_token_encrypted_response_enc');
    if (features.jwtUserinfo.enabled) {
      RECOGNIZED_METADATA.push('userinfo_encrypted_response_alg');
      RECOGNIZED_METADATA.push('userinfo_encrypted_response_enc');
    }
  }

  if (features.jwtResponseModes.enabled) {
    RECOGNIZED_METADATA.push('authorization_signed_response_alg');
    if (features.encryption.enabled) {
      RECOGNIZED_METADATA.push('authorization_encrypted_response_alg');
      RECOGNIZED_METADATA.push('authorization_encrypted_response_enc');
    }
  }

  if (features.webMessageResponseMode.enabled) {
    RECOGNIZED_METADATA.push('web_message_uris');
  }

  if (features.mTLS.enabled && features.mTLS.certificateBoundAccessTokens) {
    RECOGNIZED_METADATA.push('tls_client_certificate_bound_access_tokens');
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
      return without(configuration.idTokenSigningAlgValues, (alg) => alg === 'none');
    },
    request_object_signing_alg: () => configuration.requestObjectSigningAlgValues,
    request_object_encryption_alg: () => configuration.requestObjectEncryptionAlgValues,
    request_object_encryption_enc: () => configuration.requestObjectEncryptionEncValues,
    response_types: () => configuration.responseTypes,
    subject_type: () => configuration.subjectTypes,
    token_endpoint_auth_method: () => configuration.tokenEndpointAuthMethods,
    token_endpoint_auth_signing_alg: ({ token_endpoint_auth_method: method }) => {
      switch (method) {
        case 'private_key_jwt':
          return configuration.tokenEndpointAuthSigningAlgValues.filter((x) => !x.startsWith('HS'));
        case 'client_secret_jwt':
          return configuration.tokenEndpointAuthSigningAlgValues.filter((x) => x.startsWith('HS'));
        default:
          return [];
      }
    },
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
    introspection_endpoint_auth_signing_alg: ({ introspection_endpoint_auth_method: method }) => {
      switch (method) {
        case 'private_key_jwt':
          return configuration.introspectionEndpointAuthSigningAlgValues.filter((x) => !x.startsWith('HS'));
        case 'client_secret_jwt':
          return configuration.introspectionEndpointAuthSigningAlgValues.filter((x) => x.startsWith('HS'));
        default:
          return [];
      }
    },
    revocation_endpoint_auth_method: () => configuration.revocationEndpointAuthMethods,
    revocation_endpoint_auth_signing_alg: ({ revocation_endpoint_auth_method: method }) => {
      switch (method) {
        case 'private_key_jwt':
          return configuration.revocationEndpointAuthSigningAlgValues.filter((x) => !x.startsWith('HS'));
        case 'client_secret_jwt':
          return configuration.revocationEndpointAuthSigningAlgValues.filter((x) => x.startsWith('HS'));
        default:
          return [];
      }
    },
  };

  class Schema {
    constructor(
      metadata, ctx, processCustomMetadata = !!configuration.extraClientMetadata.properties.length,
    ) {
      // unless explicitly provided use token_* values
      ['revocation', 'introspection'].forEach((endpoint) => {
        if (metadata[`${endpoint}_endpoint_auth_method`] === undefined) {
          Object.assign(metadata, {
            [`${endpoint}_endpoint_auth_method`]: metadata.token_endpoint_auth_method || configuration.clientDefaults.token_endpoint_auth_method,
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
        omitBy(
          pick(DEFAULT, ...RECOGNIZED_METADATA),
          isUndefined,
        ),
        omitBy(
          pick(metadata, ...RECOGNIZED_METADATA, ...configuration.extraClientMetadata.properties),
          isUndefined,
        ),
      );

      this.required();
      this.booleans();
      this.whens();
      this.arrays();
      this.strings();
      this.normalizeResponseTypes();
      this.enums();
      this.webUris();
      this.scopes();
      this.postLogoutRedirectUris();
      this.redirectUris();
      this.webMessageUris();
      this.checkContacts();
      this.backchannelLogoutNeedsIdTokenAlg();
      this.jarPolicy();
      this.parPolicy();

      // max_age and client_secret_expires_at format
      ['default_max_age', 'client_secret_expires_at'].forEach((prop) => {
        if (this[prop] !== undefined) {
          if (!Number.isSafeInteger(this[prop]) || this[prop] < 0) {
            this.invalidate(`${prop} must be a non-negative integer`);
          }
        }
      });

      const responseTypes = [
        ...new Set(this.response_types.map((rt) => rt.split(' '))),
      ].reduce((acc, val) => ([...acc, ...val]), []);

      if (this.grant_types.some((type) => ['authorization_code', 'implicit'].includes(type)) && !this.response_types.length) {
        this.invalidate('response_types must contain members');
      }

      if (responseTypes.length && !this.redirect_uris.length) {
        this.invalidate('redirect_uris must contain members');
      }

      if (responseTypes.includes('code') && !this.grant_types.includes('authorization_code')) {
        this.invalidate("grant_types must contain 'authorization_code' when code is amongst response_types");
      }

      if (responseTypes.includes('token') || responseTypes.includes('id_token')) {
        if (!this.grant_types.includes('implicit')) {
          this.invalidate("grant_types must contain 'implicit' when 'id_token' or 'token' are amongst response_types");
        }
      }
      {
        const { length } = [
          this.tls_client_auth_san_dns,
          this.tls_client_auth_san_email,
          this.tls_client_auth_san_ip,
          this.tls_client_auth_san_uri,
          this.tls_client_auth_subject_dn,
        ].filter(Boolean);

        let used;
        for (const endpoint of clientAuthEndpoints) { // eslint-disable-line no-restricted-syntax
          if (this[`${endpoint}_endpoint_auth_method`] === 'tls_client_auth') {
            if (length === 0) {
              this.invalidate('tls_client_auth requires one of the certificate subject value parameters');
            }

            if (length !== 1) {
              this.invalidate('only one tls_client_auth certificate subject value must be provided');
            }

            used = true;

            break;
          }
        }

        if (length && !used) {
          delete this.tls_client_auth_san_dns;
          delete this.tls_client_auth_san_email;
          delete this.tls_client_auth_san_ip;
          delete this.tls_client_auth_san_uri;
          delete this.tls_client_auth_subject_dn;
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
        this.invalidate('jwks and jwks_uri must not be used at the same time');
      }

      if (this.jwks !== undefined) {
        if (!Array.isArray(this.jwks.keys)) {
          this.invalidate('jwks must be a JWK Set');
        }
      }

      if (processCustomMetadata) {
        this.processCustomMetadata(ctx);
      }

      this.ensureStripUnrecognized();

      if (processCustomMetadata) {
        return new Schema(this, ctx, false);
      }
    }

    invalidate(message, code) { // eslint-disable-line class-methods-use-this, no-unused-vars
      throw new InvalidClientMetadata(message);
    }

    required() {
      let checked = REQUIRED;
      if (provider.Client.needsSecret(this)) {
        checked = checked.concat('client_secret');
      }

      checked.forEach((prop) => {
        if (!this[prop]) {
          this.invalidate(`${prop} is mandatory property`);
        }
      });

      const requireJwks = checkClientAuth(this)
        || (requestSignAlgRequiringJwks.test(this.request_object_signing_alg))
        || (encAlgRequiringJwks.test(this.id_token_encrypted_response_alg))
        || (encAlgRequiringJwks.test(this.userinfo_encrypted_response_alg))
        || (encAlgRequiringJwks.test(this.introspection_encrypted_response_alg))
        || (encAlgRequiringJwks.test(this.authorization_encrypted_response_alg));

      if (requireJwks && !this.jwks && !this.jwks_uri) {
        this.invalidate('jwks or jwks_uri is mandatory for this client');
      }
    }

    strings() {
      STRING.forEach((prop) => {
        if (this[prop] !== undefined) {
          const isAry = ARYS.includes(prop);
          (isAry ? this[prop] : [this[prop]]).forEach((val) => {
            if (typeof val !== 'string' || !val.length) {
              this.invalidate(isAry
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
              this.invalidate(isAry
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
            this.invalidate(`${prop} must be an array`);
          }
          this[prop] = [...new Set(this[prop])];
        }
      });
    }

    booleans() {
      BOOL.forEach((prop) => {
        if (this[prop] !== undefined) {
          if (typeof this[prop] !== 'boolean') {
            this.invalidate(`${prop} must be a boolean`);
          }
        }
      });
    }

    whens() {
      Object.entries(WHEN).forEach(([when, [property, value]]) => {
        if (this[when] !== undefined && this[property] === undefined) {
          this.invalidate(`${property} is mandatory property when ${when} is provided`);
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
          let length;
          let method;
          if (only instanceof Set) {
            ({ size: length } = only);
            method = 'has';
          } else {
            ({ length } = only);
            method = 'includes';
          }

          if (isAry && !this[prop].every((val) => only[method](val))) {
            if (length) {
              this.invalidate(`${prop} can only contain ${formatters.formatList([...only], { type: 'disjunction' })}`);
            } else {
              this.invalidate(`${prop} must be empty (no values are allowed)`);
            }
          } else if (!isAry && !only[method](this[prop])) {
            if (length) {
              this.invalidate(`${prop} must be ${formatters.formatList([...only], { type: 'disjunction' })}`);
            } else {
              this.invalidate(`${prop} must not be provided (no values are allowed)`);
            }
          }
        }
      });
    }

    normalizeResponseTypes() {
      this.response_types = this.response_types.map((type) => [...new Set(type.split(' '))].sort().join(' '));
    }

    postLogoutRedirectUris() {
      if (this.post_logout_redirect_uris) {
        this.post_logout_redirect_uris.forEach((uri) => {
          try {
            new url.URL(uri); // eslint-disable-line no-new
          } catch (err) {
            this.invalidate('post_logout_redirect_uris must only contain uris');
          }
        });
      }
    }

    webMessageUris() {
      if (!this.web_message_uris) return;
      this.web_message_uris.forEach((uri) => {
        let origin;
        let protocol;

        try {
          ({ origin, protocol } = new url.URL(uri));
        } catch (err) {
          this.invalidate('web_message_uris must only contain valid uris');
        }
        if (!['https:', 'http:'].includes(protocol)) {
          this.invalidate('web_message_uris must only contain web uris');
        }
        if (origin !== uri) {
          this.invalidate('web_message_uris must only contain origins');
        }
      });
    }

    redirectUris() {
      this.redirect_uris.forEach((redirectUri) => {
        let hostname;
        let protocol;
        try {
          ({ hostname, protocol } = new url.URL(redirectUri));
        } catch (err) {
          this.invalidate('redirect_uris must only contain valid uris');
        }

        const { hash } = url.parse(redirectUri);

        if (hash) {
          this.invalidate('redirect_uris must not contain fragments');
        }

        switch (this.application_type) { // eslint-disable-line default-case
          case 'web': {
            if (!['https:', 'http:'].includes(protocol)) {
              this.invalidate('redirect_uris must only contain web uris');
            }

            if (this.grant_types.includes('implicit')) {
              if (protocol === 'http:') {
                this.invalidate('redirect_uris for web clients using implicit flow MUST only register URLs using the https scheme', 'implicit-force-https');
              }

              if (hostname === 'localhost') {
                this.invalidate('redirect_uris for web clients using implicit flow must not be using localhost', 'implicit-forbid-localhost');
              }
            }
            break;
          }
          case 'native': {
            switch (protocol) {
              case 'http:': // Loopback Interface Redirection
                if (!LOOPBACKS.has(hostname)) {
                  this.invalidate('redirect_uris for native clients using http as a protocol can only use loopback addresses as hostnames');
                }
                break;
              case 'https:': // Claimed HTTPS URI Redirection
                if (LOOPBACKS.has(hostname)) {
                  this.invalidate(`redirect_uris for native clients using claimed HTTPS URIs must not be using ${hostname} as hostname`);
                }
                break;
              default: // Private-use URI Scheme Redirection
                if (!protocol.includes('.')) {
                  this.invalidate('redirect_uris for native clients using Custom URI scheme should use reverse domain name based scheme');
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
            this.invalidate('contacts can only contain email addresses');
          }
        });
      }
    }

    processCustomMetadata(ctx) {
      configuration.extraClientMetadata.properties.forEach((prop) => {
        configuration.extraClientMetadata.validator(prop, this[prop], this, ctx);
      });
    }

    parPolicy() {
      const par = configuration.features.pushedAuthorizationRequests;
      if (par.enabled && par.requirePushedAuthorizationRequests) {
        this.require_pushed_authorization_requests = true;
      }
    }

    jarPolicy() {
      const jar = configuration.features.requestObjects;
      const enabled = jar.request || jar.requestUri;
      if (enabled) {
        if (jar.requireSignedRequestObject) {
          this.require_signed_request_object = true;
        }
        if (this.require_signed_request_object && this.request_object_signing_alg === 'none') {
          this.invalidate('request_object_signing_alg must not be "none" when require_signed_request_object is true');
        }
      }
    }

    ensureStripUnrecognized() {
      const whitelisted = [...RECOGNIZED_METADATA, ...configuration.extraClientMetadata.properties];
      Object.keys(this).forEach((prop) => {
        if (!whitelisted.includes(prop)) {
          delete this[prop];
        }
      });
    }

    backchannelLogoutNeedsIdTokenAlg() {
      if (this.backchannel_logout_uri && this.id_token_signed_response_alg === 'none') {
        this.invalidate('id_token_signed_response_alg must not be "none" when backchannel_logout_uri is used');
      }
    }

    scopes() {
      if (this.scope) {
        const parsed = new Set(this.scope.split(' '));
        parsed.forEach((scope) => {
          if (!scopes.has(scope) && !dynamicScopes.has(scope)) {
            this.invalidate('scope must only contain supported scopes');
          }
        });
        this.scope = [...parsed].join(' ');
      }
    }
  }

  return Schema;
};
