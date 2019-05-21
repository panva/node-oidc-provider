/* eslint-disable max-len */

const { defaults } = require('lodash');

const instance = require('../helpers/weak_cache');

module.exports = function discoveryAction(provider) {
  const config = instance(provider).configuration();

  return async function renderConfiguration(ctx, next) {
    ctx.body = {
      acr_values_supported: config.acrValues.length ? config.acrValues : undefined,
      authorization_endpoint: ctx.oidc.urlFor('authorization'),
      claims_parameter_supported: !!config.features.claimsParameter,
      claims_supported: config.claimsSupported,
      grant_types_supported: Array.from(config.grantTypes),
      id_token_signing_alg_values_supported: config.idTokenSigningAlgValues,
      issuer: provider.issuer,
      jwks_uri: ctx.oidc.urlFor('certificates'),
      registration_endpoint: config.features.registration ? ctx.oidc.urlFor('registration') : undefined,
      request_object_signing_alg_values_supported: config.features.request || config.features.requestUri ? config.requestObjectSigningAlgValues : undefined,
      request_parameter_supported: !!config.features.request,
      request_uri_parameter_supported: !!config.features.requestUri,
      require_request_uri_registration: config.features.requestUri && config.features.requestUri.requireRequestUriRegistration ? true : undefined,
      response_modes_supported: ['form_post', 'fragment', 'query'],
      response_types_supported: config.responseTypes,
      scopes_supported: config.scopes,
      subject_types_supported: config.subjectTypes,
      token_endpoint: ctx.oidc.urlFor('token'),
      token_endpoint_auth_methods_supported: config.tokenEndpointAuthMethods,
      token_endpoint_auth_signing_alg_values_supported: config.tokenEndpointAuthSigningAlgValues,
      userinfo_endpoint: ctx.oidc.urlFor('userinfo'),
      userinfo_signing_alg_values_supported: config.userinfoSigningAlgValues,
      code_challenge_methods_supported: config.features.pkce ? config.features.pkce.supportedMethods : undefined,
    };

    if (config.features.webMessageResponseMode) {
      ctx.body.response_modes_supported.push('web_message');
    }

    if (config.features.jwtResponseModes) {
      ctx.body.response_modes_supported.push('jwt');

      ctx.body.response_modes_supported.push('query.jwt');
      ctx.body.response_modes_supported.push('fragment.jwt');
      ctx.body.response_modes_supported.push('form_post.jwt');

      if (config.features.webMessageResponseMode) {
        ctx.body.response_modes_supported.push('web_message.jwt');
      }

      ctx.body.authorization_signing_alg_values_supported = config.authorizationSigningAlgValues;
    }

    if (config.features.introspection) {
      ctx.body.introspection_endpoint = ctx.oidc.urlFor('introspection');
      ctx.body.introspection_endpoint_auth_methods_supported = config.introspectionEndpointAuthMethods;
      ctx.body.introspection_endpoint_auth_signing_alg_values_supported = config.introspectionEndpointAuthSigningAlgValues;
    }

    if (config.features.jwtIntrospection) {
      ctx.body.introspection_endpoint_signing_alg_values_supported = config.introspectionSigningAlgValues;
    }

    if (config.features.revocation) {
      ctx.body.revocation_endpoint = ctx.oidc.urlFor('revocation');
      ctx.body.revocation_endpoint_auth_methods_supported = config.revocationEndpointAuthMethods;
      ctx.body.revocation_endpoint_auth_signing_alg_values_supported = config.revocationEndpointAuthSigningAlgValues;
    }

    if (config.features.encryption) {
      ctx.body.id_token_encryption_alg_values_supported = config.idTokenEncryptionAlgValues;
      ctx.body.id_token_encryption_enc_values_supported = config.idTokenEncryptionEncValues;
      ctx.body.userinfo_encryption_alg_values_supported = config.userinfoEncryptionAlgValues;
      ctx.body.userinfo_encryption_enc_values_supported = config.userinfoEncryptionEncValues;

      if (config.features.jwtIntrospection) {
        ctx.body.introspection_encryption_alg_values_supported = config.introspectionEncryptionAlgValues;
        ctx.body.introspection_encryption_enc_values_supported = config.introspectionEncryptionEncValues;
      }

      if (config.features.jwtResponseModes) {
        ctx.body.authorization_encryption_alg_values_supported = config.authorizationEncryptionAlgValues;
        ctx.body.authorization_encryption_enc_values_supported = config.authorizationEncryptionEncValues;
      }

      if (config.features.request || config.features.requestUri) {
        ctx.body.request_object_encryption_alg_values_supported = config.requestObjectEncryptionAlgValues;
        ctx.body.request_object_encryption_enc_values_supported = config.requestObjectEncryptionEncValues;
      }
    }

    if (
      config.features.sessionManagement
      || config.features.backchannelLogout
      || config.features.frontchannelLogout
    ) {
      ctx.body.end_session_endpoint = ctx.oidc.urlFor('end_session');
    }

    if (config.features.sessionManagement) {
      ctx.body.check_session_iframe = ctx.oidc.urlFor('check_session');
    }

    if (config.features.backchannelLogout) {
      ctx.body.backchannel_logout_supported = true;
      ctx.body.backchannel_logout_session_supported = true;
    }

    if (config.features.frontchannelLogout) {
      ctx.body.frontchannel_logout_supported = true;
      ctx.body.frontchannel_logout_session_supported = true;
    }

    if (config.features.deviceFlow) {
      ctx.body.device_authorization_endpoint = ctx.oidc.urlFor('device_authorization');
    }

    if (config.features.certificateBoundAccessTokens) {
      ctx.body.tls_client_certificate_bound_access_tokens = true;
    }

    defaults(ctx.body, config.discovery);

    await next();
  };
};
