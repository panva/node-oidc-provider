import { CLIENT_ATTRIBUTES } from '../consts/index.js';

import * as validUrl from './valid_url.js';
import { InvalidClientMetadata } from './errors.js';
import sectorIdentifier from './sector_identifier.js';
import instance from './weak_cache.js';
import * as formatters from './formatters.js';
import pick from './_/pick.js';
import omitBy from './_/omit_by.js';

const W3CEmailRegExp = /^[a-zA-Z0-9.!#$%&’*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/;
const needsJwks = {
  jwe: /^(RSA|ECDH)/,
  jws: /^(?:PS(?:256|384|512)|RS(?:256|384|512)|ES(?:256|384|512)|EdDSA)$/,
};
const {
  ARYS,
  BOOL,
  DEFAULT: DEFAULTS,
  ENUM: ENUMS,
  HTTPS_URI,
  LOOPBACKS,
  RECOGNIZED_METADATA: RECOGNIZED,
  REQUIRED,
  STRING,
  SYNTAX,
  WEB_URI,
  WHEN,
} = CLIENT_ATTRIBUTES;

function isUndefined(value) {
  return value === undefined;
}

export default function getSchema(provider) {
  const configuration = instance(provider).configuration();
  const { features } = configuration;

  const { scopes } = configuration;

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
    RECOGNIZED_METADATA.push('use_mtls_endpoint_aliases');
  }

  if (configuration.clientAuthSigningAlgValues) {
    RECOGNIZED_METADATA.push('token_endpoint_auth_signing_alg');
  }

  if (features.jwtUserinfo.enabled) {
    RECOGNIZED_METADATA.push('userinfo_signed_response_alg');
  }

  if (features.introspection.enabled) {
    if (features.jwtIntrospection.enabled) {
      RECOGNIZED_METADATA.push('introspection_signed_response_alg');

      if (features.encryption.enabled) {
        RECOGNIZED_METADATA.push('introspection_encrypted_response_alg');
        RECOGNIZED_METADATA.push('introspection_encrypted_response_enc');
      }
    }
  }

  if (features.rpInitiatedLogout.enabled) {
    RECOGNIZED_METADATA.push('post_logout_redirect_uris');
  }

  if (features.backchannelLogout.enabled) {
    RECOGNIZED_METADATA.push('backchannel_logout_session_required');
    RECOGNIZED_METADATA.push('backchannel_logout_uri');
  }

  if (
    features.requestObjects.request
    || features.requestObjects.requestUri
  ) {
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

  if (features.mTLS.enabled && features.mTLS.certificateBoundAccessTokens) {
    RECOGNIZED_METADATA.push('tls_client_certificate_bound_access_tokens');
  }

  if (features.ciba.enabled) {
    RECOGNIZED_METADATA.push('backchannel_token_delivery_mode');
    RECOGNIZED_METADATA.push('backchannel_user_code_parameter');
    RECOGNIZED_METADATA.push('backchannel_client_notification_endpoint');
    if (features.requestObjects.request) {
      RECOGNIZED_METADATA.push('backchannel_authentication_request_signing_alg');
    }
  }

  if (features.dPoP.enabled) {
    RECOGNIZED_METADATA.push('dpop_bound_access_tokens');
  }

  if (features.richAuthorizationRequests.enabled) {
    RECOGNIZED_METADATA.push('authorization_details_types');
  }

  instance(provider).RECOGNIZED_METADATA = RECOGNIZED_METADATA;

  const ENUM = {
    ...ENUMS,
    default_acr_values: () => configuration.acrValues,
    grant_types: () => configuration.grantTypes,
    id_token_encrypted_response_alg: () => configuration.idTokenEncryptionAlgValues,
    id_token_encrypted_response_enc: () => configuration.idTokenEncryptionEncValues,
    id_token_signed_response_alg: () => configuration.idTokenSigningAlgValues,
    request_object_signing_alg: () => configuration.requestObjectSigningAlgValues,
    backchannel_token_delivery_mode: () => features.ciba.deliveryModes,
    backchannel_authentication_request_signing_alg: () => configuration.requestObjectSigningAlgValues.filter((alg) => !alg.startsWith('HS')),
    request_object_encryption_alg: () => configuration.requestObjectEncryptionAlgValues,
    request_object_encryption_enc: () => configuration.requestObjectEncryptionEncValues,
    response_types: () => configuration.responseTypes,
    response_modes: () => [...instance(provider).responseModes.keys()],
    subject_type: () => configuration.subjectTypes,
    authorization_details_types:
      () => Object.keys(configuration.features.richAuthorizationRequests.types),
    token_endpoint_auth_method: (metadata) => {
      if (metadata.subject_type === 'pairwise') {
        for (const grant of ['urn:ietf:params:oauth:grant-type:device_code', 'urn:openid:params:grant-type:ciba']) {
          if (metadata.grant_types.includes(grant) && !['private_key_jwt', 'self_signed_tls_client_auth'].includes(metadata.token_endpoint_auth_method)) {
            metadata.invalidate(`pairwise ${grant} clients must utilize private_key_jwt or self_signed_tls_client_auth token endpoint authentication methods`);
          }
        }
      }

      return configuration.clientAuthMethods;
    },
    token_endpoint_auth_signing_alg: ({ token_endpoint_auth_method: method }) => {
      switch (method) {
        case 'private_key_jwt':
          return configuration.clientAuthSigningAlgValues.filter((x) => !x.startsWith('HS'));
        case 'client_secret_jwt':
          return configuration.clientAuthSigningAlgValues.filter((x) => x.startsWith('HS'));
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
  };

  class Schema {
    constructor(
      metadata,
      ctx,
      processCustomMetadata = !!configuration.extraClientMetadata.properties.length,
    ) {
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
      this.syntax();
      this.normalizeResponseTypes();
      this.enums();
      this.webUris();
      this.scopes();
      this.postLogoutRedirectUris();
      this.redirectUris();
      this.checkContacts();
      this.jarPolicy();
      this.parPolicy();

      // max_age and client_secret_expires_at format
      ['default_max_age', 'client_secret_expires_at'].forEach((prop) => {
        if (this[prop] !== undefined) {
          if (!Number.isSafeInteger(this[prop]) || Math.sign(this[prop]) === -1) {
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
        const { pushedAuthorizationRequests: par } = features;
        if (
          !par.enabled
          || !par.allowUnregisteredRedirectUris
          || !this.require_pushed_authorization_requests
          || this.token_endpoint_auth_method === 'none'
          || this.sector_identifier_uri
        ) {
          this.invalidate('redirect_uris must contain members');
        }
      }

      if (responseTypes.length && this.response_modes?.length === 0) {
        this.invalidate('response_modes must contain members');
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
        const { 0: pop, length } = [
          'tls_client_certificate_bound_access_tokens',
          'dpop_bound_access_tokens',
        ].filter((conf) => this[conf]);

        if (length > 1) {
          this.invalidate('only one proof of possession mechanism can be made required at a time');
        }

        if (length !== 0 && responseTypes.includes('token')) {
          this.invalidate(`response_types must not include "token" when ${pop} is used`);
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

        if (this.token_endpoint_auth_method === 'tls_client_auth') {
          if (length === 0) {
            this.invalidate('tls_client_auth requires one of the certificate subject value parameters');
          }

          if (length !== 1) {
            this.invalidate('only one tls_client_auth certificate subject value must be provided');
          }
        } else {
          delete this.tls_client_auth_san_dns;
          delete this.tls_client_auth_san_email;
          delete this.tls_client_auth_san_ip;
          delete this.tls_client_auth_san_uri;
          delete this.tls_client_auth_subject_dn;
        }
      }

      // SECTOR IDENTIFIER VALIDATION
      sectorIdentifier(this);

      if (this.jwks !== undefined && this.jwks_uri !== undefined) {
        this.invalidate('jwks and jwks_uri must not be used at the same time');
      }

      if (processCustomMetadata) {
        this.processCustomMetadata(ctx);
      }

      this.ensureStripUnrecognized();

      if (processCustomMetadata) {
        // eslint-disable-next-line no-constructor-return
        return new Schema(this, ctx, false);
      }
    }

    invalidate(message, code) { // eslint-disable-line class-methods-use-this, no-unused-vars
      throw new InvalidClientMetadata(message);
    }

    required() {
      const checked = REQUIRED.slice();
      if (provider.Client.needsSecret(this)) {
        checked.push('client_secret');
      }

      if (Array.isArray(this.response_types) && this.response_types.length) {
        checked.push('redirect_uris');
      } else if (this.redirect_uris === undefined) {
        this.redirect_uris = [];
      }

      if (Array.isArray(this.grant_types) && this.grant_types.includes('urn:openid:params:grant-type:ciba')) {
        checked.push('backchannel_token_delivery_mode');
        if (this.backchannel_token_delivery_mode !== 'poll') {
          checked.push('backchannel_client_notification_endpoint');
        }

        if (this.subject_type === 'pairwise') {
          checked.push('jwks_uri');
          if (Array.isArray(this.response_types) && this.response_types.length) {
            checked.push('sector_identifier_uri');
          }
        }
      }

      if (this.subject_type === 'pairwise') {
        if (
          Array.isArray(this.grant_types)
          && this.grant_types.includes('urn:ietf:params:oauth:grant-type:device_code')
        ) {
          checked.push('jwks_uri');
          if (Array.isArray(this.response_types) && this.response_types.length) {
            checked.push('sector_identifier_uri');
          }
        }

        if (
          Array.isArray(this.response_types)
          && this.response_types.length
          && Array.isArray(this.redirect_uris)
          && new Set(this.redirect_uris.map((uri) => new URL(uri).host)).size > 1
        ) {
          checked.push('sector_identifier_uri');
        }
      }

      checked.forEach((prop) => {
        if (!this[prop]) {
          this.invalidate(`${prop} is mandatory property`);
        }
      });

      const requireJwks = ['private_key_jwt', 'self_signed_tls_client_auth'].includes(this.token_endpoint_auth_method)
        || (needsJwks.jws.test(this.request_object_signing_alg))
        || (needsJwks.jws.test(this.backchannel_authentication_request_signing_alg))
        || (needsJwks.jwe.test(this.id_token_encrypted_response_alg))
        || (needsJwks.jwe.test(this.userinfo_encrypted_response_alg))
        || (needsJwks.jwe.test(this.introspection_encrypted_response_alg))
        || (needsJwks.jwe.test(this.authorization_encrypted_response_alg));

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
        }

        if (value && this[when] === undefined && this[property] !== undefined) {
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
        this.redirectUris(this.post_logout_redirect_uris, 'post_logout_redirect_uris');
      }
    }

    redirectUris(uris = this.redirect_uris, label = 'redirect_uris') {
      uris.forEach((redirectUri) => {
        let hostname;
        let protocol;
        let hash;
        try {
          ({ hostname, protocol, hash } = new URL(redirectUri));
        } catch (err) {
          this.invalidate(`${label} must only contain valid uris`);
        }

        if (hash) {
          this.invalidate(`${label} must not contain fragments`);
        }

        switch (this.application_type) { // eslint-disable-line default-case
          case 'web': {
            if (!['https:', 'http:'].includes(protocol)) {
              this.invalidate(`${label} must only contain web uris`);
            }

            if (this.grant_types.includes('implicit')) {
              if (protocol === 'http:') {
                this.invalidate(`${label} for web clients using implicit flow MUST only register URLs using the https scheme`, 'implicit-force-https');
              }

              if (hostname === 'localhost') {
                this.invalidate(`${label} for web clients using implicit flow must not be using localhost`, 'implicit-forbid-localhost');
              }
            }
            break;
          }
          case 'native': {
            switch (protocol) {
              case 'http:': // Loopback Interface Redirection
                if (!LOOPBACKS.has(hostname)) {
                  this.invalidate(`${label} for native clients using http as a protocol can only use loopback addresses as hostnames`);
                }
                break;
              case 'https:': // Claimed HTTPS URI Redirection
                if (LOOPBACKS.has(hostname)) {
                  this.invalidate(`${label} for native clients using claimed HTTPS URIs must not be using ${hostname} as hostname`);
                }
                break;
              default: // Private-use URI Scheme Redirection
                if (!protocol.includes('.')) {
                  this.invalidate(`${label} for native clients using Custom URI scheme should use reverse domain name based scheme`);
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
        configuration.extraClientMetadata.validator(ctx, prop, this[prop], this);
      });
    }

    parPolicy() {
      const par = configuration.features.pushedAuthorizationRequests;
      if (par.enabled && par.requirePushedAuthorizationRequests) {
        this.require_pushed_authorization_requests = true;
      }
    }

    jarPolicy() {
      const { features: { requestObjects } } = configuration;

      const enabled = requestObjects.request
        || requestObjects.requestUri;

      if (enabled) {
        if (requestObjects.requireSignedRequestObject) {
          this.require_signed_request_object = true;
        }
      }
    }

    ensureStripUnrecognized() {
      const allowed = [...RECOGNIZED_METADATA, ...configuration.extraClientMetadata.properties];
      Object.keys(this).forEach((prop) => {
        if (!allowed.includes(prop)) {
          delete this[prop];
        }
      });
    }

    scopes() {
      if (this.scope) {
        const parsed = new Set(this.scope.split(' '));
        parsed.forEach((scope) => {
          if (!scopes.has(scope)) {
            this.invalidate('scope must only contain Authorization Server supported scope values');
          }
        });
        this.scope = [...parsed].join(' ');
      }
    }

    syntax() {
      for (const [prop, regexp] of Object.entries(SYNTAX)) {
        if (regexp.exec(this[prop])) {
          this.invalidate(`invalid ${prop} value`);
        }
      }
    }
  }

  return Schema;
}
