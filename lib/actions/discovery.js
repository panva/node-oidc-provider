'use strict';

module.exports = function(provider) {

  // TODO: pass over config (somehting is under openid something's not)

  let config = provider.configuration;

  return function * renderConfiguration(next) {

    this.body = {
      acr_values_supported: config.acrValuesSupported,
      authorization_endpoint: this.oidc.urlFor('authentication'),
      claims_parameter_supported: !!config.features.claimsParameter,
      claims_supported: config.claimsSupported,
      grant_types_supported: config.grantTypesSupported,
      id_token_signing_alg_values_supported:
        config.idTokenSigningAlgValuesSupported,
      issuer: provider.issuer,
      jwks_uri: this.oidc.urlFor('certificates'),
      registration_endpoint: config.features.registration ?
        this.oidc.urlFor('registration') : undefined,
      request_object_signing_alg_values_supported:
        config.features.request || config.features.requestUri ?
          config.requestObjectSigningAlgValuesSupported : undefined,
      request_parameter_supported: !!config.features.request,
      request_uri_parameter_supported: !!config.features.requestUri,
      response_modes_supported: [
        'form_post',
        'fragment',
        'query',
      ],
      response_types_supported: config.responseTypesSupported,
      scopes_supported: config.scopes,
      subject_types_supported: config.subjectTypesSupported,
      token_endpoint: this.oidc.urlFor('token'),
      token_endpoint_auth_methods_supported:
        config.tokenEndpointAuthMethodsSupported,
      token_endpoint_auth_signing_alg_values_supported:
        config.tokenEndpointAuthMethodsSupported.join('').includes('_jwt') ?
          config.tokenEndpointAuthSigningAlgValuesSupported : undefined,
      token_introspection_endpoint: config.features.introspection ?
        this.oidc.urlFor('introspection') : undefined,
      token_revocation_endpoint: config.features.revocation ?
        this.oidc.urlFor('revocation') : undefined,
      userinfo_endpoint: this.oidc.urlFor('userinfo'),
      userinfo_signing_alg_values_supported:
        config.userinfoSigningAlgValuesSupported,
    };

    if (config.features.encryption) {
      this.body.id_token_encryption_alg_values_supported =
        config.idTokenEncryptionAlgValuesSupported;
      this.body.id_token_encryption_enc_values_supported =
        config.idTokenEncryptionEncValuesSupported;
      this.body.userinfo_encryption_alg_values_supported =
        config.userinfoEncryptionAlgValuesSupported;
      this.body.userinfo_encryption_enc_values_supported =
        config.userinfoEncryptionEncValuesSupported;

      if (config.features.request || config.features.requestUri) {
        this.body.request_object_encryption_alg_values_supported =
          config.requestObjectEncryptionAlgValuesSupported;
        this.body.request_object_encryption_enc_values_supported =
          config.requestObjectEncryptionEncValuesSupported;
      }

    }

    if (config.features.sessionManagement) {
      this.body.check_session_iframe = this.oidc.urlFor('check_session');
      this.body.end_session_endpoint = this.oidc.urlFor('end_session');
    }

    yield next;
  };
};
