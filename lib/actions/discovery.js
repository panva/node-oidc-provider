/* eslint-disable max-len */

const { defaults } = require('lodash');

const instance = require('../helpers/weak_cache');
const { DYNAMIC_SCOPE_LABEL } = require('../consts');

module.exports = function discovery(ctx, next) {
  const config = instance(ctx.oidc.provider).configuration();

  ctx.body = {
    acr_values_supported: config.acrValues.size ? [...config.acrValues] : undefined,
    authorization_endpoint: ctx.oidc.urlFor('authorization'),
    claims_parameter_supported: config.features.claimsParameter.enabled,
    claims_supported: [...config.claimsSupported],
    code_challenge_methods_supported: config.pkceMethods,
    end_session_endpoint: ctx.oidc.urlFor('end_session'),
    grant_types_supported: [...config.grantTypes],
    id_token_signing_alg_values_supported: config.idTokenSigningAlgValues,
    issuer: ctx.oidc.issuer,
    jwks_uri: ctx.oidc.urlFor('jwks'),
    registration_endpoint: config.features.registration.enabled ? ctx.oidc.urlFor('registration') : undefined,
    request_object_signing_alg_values_supported: config.features.request.enabled || config.features.requestUri.enabled ? config.requestObjectSigningAlgValues : undefined,
    request_parameter_supported: config.features.request.enabled,
    request_uri_parameter_supported: config.features.requestUri.enabled,
    require_request_uri_registration: config.features.requestUri.enabled && config.features.requestUri.requireUriRegistration ? true : undefined,
    response_modes_supported: ['form_post', 'fragment', 'query'],
    response_types_supported: config.responseTypes,
    scopes_supported: [...config.scopes].concat([...config.dynamicScopes].map(s => s[DYNAMIC_SCOPE_LABEL]).filter(Boolean)),
    subject_types_supported: [...config.subjectTypes],
    token_endpoint_auth_methods_supported: [...config.tokenEndpointAuthMethods],
    token_endpoint_auth_signing_alg_values_supported: config.tokenEndpointAuthSigningAlgValues,
    token_endpoint: ctx.oidc.urlFor('token'),
  };

  if (config.features.userinfo.enabled) {
    ctx.body.userinfo_endpoint = ctx.oidc.urlFor('userinfo');
    if (config.features.jwtUserinfo.enabled) {
      ctx.body.userinfo_signing_alg_values_supported = config.userinfoSigningAlgValues;
    }
  }

  if (config.features.webMessageResponseMode.enabled) {
    ctx.body.response_modes_supported.push('web_message');
  }

  if (config.features.jwtResponseModes.enabled) {
    ctx.body.response_modes_supported.push('jwt');

    ctx.body.response_modes_supported.push('query.jwt');
    ctx.body.response_modes_supported.push('fragment.jwt');
    ctx.body.response_modes_supported.push('form_post.jwt');

    if (config.features.webMessageResponseMode.enabled) {
      ctx.body.response_modes_supported.push('web_message.jwt');
    }

    ctx.body.authorization_signing_alg_values_supported = config.authorizationSigningAlgValues;
  }

  if (config.features.introspection.enabled) {
    ctx.body.introspection_endpoint = ctx.oidc.urlFor('introspection');
    ctx.body.introspection_endpoint_auth_methods_supported = [...config.introspectionEndpointAuthMethods];
    ctx.body.introspection_endpoint_auth_signing_alg_values_supported = config.introspectionEndpointAuthSigningAlgValues;
  }

  if (config.features.jwtIntrospection.enabled) {
    ctx.body.introspection_signing_alg_values_supported = config.introspectionSigningAlgValues;
  }

  if (config.features.revocation.enabled) {
    ctx.body.revocation_endpoint = ctx.oidc.urlFor('revocation');
    ctx.body.revocation_endpoint_auth_methods_supported = [...config.revocationEndpointAuthMethods];
    ctx.body.revocation_endpoint_auth_signing_alg_values_supported = config.revocationEndpointAuthSigningAlgValues;
  }

  if (config.features.encryption.enabled) {
    ctx.body.id_token_encryption_alg_values_supported = config.idTokenEncryptionAlgValues;
    ctx.body.id_token_encryption_enc_values_supported = config.idTokenEncryptionEncValues;

    if (config.features.jwtUserinfo.enabled) {
      ctx.body.userinfo_encryption_alg_values_supported = config.userinfoEncryptionAlgValues;
      ctx.body.userinfo_encryption_enc_values_supported = config.userinfoEncryptionEncValues;
    }

    if (config.features.jwtIntrospection.enabled) {
      ctx.body.introspection_encryption_alg_values_supported = config.introspectionEncryptionAlgValues;
      ctx.body.introspection_encryption_enc_values_supported = config.introspectionEncryptionEncValues;
    }

    if (config.features.jwtResponseModes.enabled) {
      ctx.body.authorization_encryption_alg_values_supported = config.authorizationEncryptionAlgValues;
      ctx.body.authorization_encryption_enc_values_supported = config.authorizationEncryptionEncValues;
    }

    if (config.features.request.enabled || config.features.requestUri.enabled) {
      ctx.body.request_object_encryption_alg_values_supported = config.requestObjectEncryptionAlgValues;
      ctx.body.request_object_encryption_enc_values_supported = config.requestObjectEncryptionEncValues;
    }
  }

  if (config.features.sessionManagement.enabled) {
    ctx.body.check_session_iframe = ctx.oidc.urlFor('check_session');
  }

  if (config.features.backchannelLogout.enabled) {
    ctx.body.backchannel_logout_supported = true;
    ctx.body.backchannel_logout_session_supported = true;
  }

  if (config.features.frontchannelLogout.enabled) {
    ctx.body.frontchannel_logout_supported = true;
    ctx.body.frontchannel_logout_session_supported = true;
  }

  if (config.features.deviceFlow.enabled) {
    ctx.body.device_authorization_endpoint = ctx.oidc.urlFor('device_authorization');
  }

  if (config.features.certificateBoundAccessTokens.enabled) {
    ctx.body.tls_client_certificate_bound_access_tokens = true;
  }

  defaults(ctx.body, config.discovery);

  return next();
};
