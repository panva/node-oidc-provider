'use strict';

const _ = require('lodash');
const instance = require('../helpers/weak_cache');

module.exports = function discoveryAction(provider) {
  const config = instance(provider).configuration();

  return function* renderConfiguration(next) {
    this.body = {
      acr_values_supported: config.acrValues.length ? config.acrValues : undefined,
      authorization_endpoint: this.oidc.urlFor('authorization'),
      claims_parameter_supported: !!config.features.claimsParameter,
      claims_supported: config.claimsSupported,
      grant_types_supported: Array.from(config.grantTypes),
      id_token_signing_alg_values_supported: config.idTokenSigningAlgValues,
      issuer: provider.issuer,
      jwks_uri: this.oidc.urlFor('certificates'),
      registration_endpoint: config.features.registration ?
        this.oidc.urlFor('registration') : undefined,
      request_object_signing_alg_values_supported:
        config.features.request || config.features.requestUri ?
          config.requestObjectSigningAlgValues : undefined,
      request_parameter_supported: !!config.features.request,
      request_uri_parameter_supported: !!config.features.requestUri,
      require_request_uri_registration: config.features.requestUri ?
        config.features.requestUri.requireRequestUriRegistration : undefined,
      response_modes_supported: [
        'form_post',
        'fragment',
        'query',
      ],
      response_types_supported: config.responseTypes,
      scopes_supported: config.scopes,
      subject_types_supported: config.subjectTypes,
      token_endpoint: this.oidc.urlFor('token'),
      token_endpoint_auth_methods_supported: config.tokenEndpointAuthMethods,
      token_endpoint_auth_signing_alg_values_supported: config.tokenEndpointAuthSigningAlgValues,
      userinfo_endpoint: this.oidc.urlFor('userinfo'),
      userinfo_signing_alg_values_supported: config.userinfoSigningAlgValues,
      code_challenge_methods_supported: ['plain', 'S256'],
    };

    if (config.features.introspection) {
      this.body.introspection_endpoint = this.oidc.urlFor('introspection');
      this.body.introspection_endpoint_auth_methods_supported =
        config.introspectionEndpointAuthMethods;
      this.body.introspection_endpoint_auth_signing_alg_values_supported =
        config.introspectionEndpointAuthSigningAlgValues;
    }

    if (config.features.revocation) {
      this.body.revocation_endpoint = this.oidc.urlFor('revocation');
      this.body.revocation_endpoint_auth_methods_supported =
        config.introspectionEndpointAuthMethods;
      this.body.revocation_endpoint_auth_signing_alg_values_supported =
        config.introspectionEndpointAuthSigningAlgValues;
    }

    this.body.token_introspection_endpoint = this.body.introspection_endpoint; // 2.0 DEPRECATED
    this.body.token_revocation_endpoint = this.body.revocation_endpoint; // 2.0 DEPRECATED

    if (config.features.encryption) {
      this.body.id_token_encryption_alg_values_supported = config.idTokenEncryptionAlgValues;
      this.body.id_token_encryption_enc_values_supported = config.idTokenEncryptionEncValues;
      this.body.userinfo_encryption_alg_values_supported = config.userinfoEncryptionAlgValues;
      this.body.userinfo_encryption_enc_values_supported = config.userinfoEncryptionEncValues;

      if (config.features.request || config.features.requestUri) {
        this.body.request_object_encryption_alg_values_supported =
          config.requestObjectEncryptionAlgValues;
        this.body.request_object_encryption_enc_values_supported =
          config.requestObjectEncryptionEncValues;
      }
    }

    if (config.features.sessionManagement) {
      this.body.check_session_iframe = this.oidc.urlFor('check_session');
      this.body.end_session_endpoint = this.oidc.urlFor('end_session');

      if (config.features.backchannelLogout) {
        this.body.backchannel_logout_supported = true;
        this.body.backchannel_logout_session_supported = true;
      }
    }

    _.defaults(this.body, config.discovery);

    yield next;
  };
};
