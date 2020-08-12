/* eslint-disable max-len */

const defaults = require('../helpers/_/defaults');
const instance = require('../helpers/weak_cache');
const { DYNAMIC_SCOPE_LABEL } = require('../consts');

module.exports = function discovery(ctx, next) {
  const config = instance(ctx.oidc.provider).configuration();
  const { features } = config;

  ctx.body = {
    acr_values_supported: config.acrValues.size ? [...config.acrValues] : undefined,
    authorization_endpoint: ctx.oidc.urlFor('authorization'),
    device_authorization_endpoint: features.deviceFlow.enabled ? ctx.oidc.urlFor('device_authorization') : undefined,
    claims_parameter_supported: features.claimsParameter.enabled,
    claims_supported: [...config.claimsSupported],
    code_challenge_methods_supported: config.pkce.methods,
    end_session_endpoint: features.rpInitiatedLogout.enabled ? ctx.oidc.urlFor('end_session') : undefined,
    check_session_iframe: features.sessionManagement.enabled ? ctx.oidc.urlFor('check_session') : undefined,
    grant_types_supported: [...config.grantTypes],
    id_token_signing_alg_values_supported: config.idTokenSigningAlgValues,
    issuer: ctx.oidc.issuer,
    jwks_uri: ctx.oidc.urlFor('jwks'),
    registration_endpoint: features.registration.enabled ? ctx.oidc.urlFor('registration') : undefined,
    response_modes_supported: ['form_post', 'fragment', 'query'],
    response_types_supported: config.responseTypes,
    scopes_supported: [...config.scopes].concat([...config.dynamicScopes].map((s) => s[DYNAMIC_SCOPE_LABEL]).filter(Boolean)),
    subject_types_supported: [...config.subjectTypes],
    token_endpoint_auth_methods_supported: [...config.tokenEndpointAuthMethods],
    token_endpoint_auth_signing_alg_values_supported: config.tokenEndpointAuthSigningAlgValues,
    token_endpoint: ctx.oidc.urlFor('token'),
  };

  if (features.pushedAuthorizationRequests.enabled) {
    ctx.body.pushed_authorization_request_endpoint = ctx.oidc.urlFor('pushed_authorization_request');
    ctx.body.require_pushed_authorization_requests = features.pushedAuthorizationRequests.requirePushedAuthorizationRequests ? true : undefined;
  }

  const { requestObjects } = features;
  if (requestObjects.request || requestObjects.requestUri) {
    ctx.body.request_object_signing_alg_values_supported = config.requestObjectSigningAlgValues;
    ctx.body.request_parameter_supported = requestObjects.request;
    ctx.body.request_uri_parameter_supported = requestObjects.requestUri;
    ctx.body.require_request_uri_registration = requestObjects.requireUriRegistration ? true : undefined;
    ctx.body.require_signed_request_object = requestObjects.requireSignedRequestObject ? true : undefined;
  }

  if (features.userinfo.enabled) {
    ctx.body.userinfo_endpoint = ctx.oidc.urlFor('userinfo');
    if (features.jwtUserinfo.enabled) {
      ctx.body.userinfo_signing_alg_values_supported = config.userinfoSigningAlgValues;
    }
  }

  if (features.webMessageResponseMode.enabled) {
    ctx.body.response_modes_supported.push('web_message');
  }

  if (features.jwtResponseModes.enabled) {
    ctx.body.response_modes_supported.push('jwt');

    ctx.body.response_modes_supported.push('query.jwt');
    ctx.body.response_modes_supported.push('fragment.jwt');
    ctx.body.response_modes_supported.push('form_post.jwt');

    if (features.webMessageResponseMode.enabled) {
      ctx.body.response_modes_supported.push('web_message.jwt');
    }

    ctx.body.authorization_signing_alg_values_supported = config.authorizationSigningAlgValues;
  }

  if (features.introspection.enabled) {
    ctx.body.introspection_endpoint = ctx.oidc.urlFor('introspection');
    ctx.body.introspection_endpoint_auth_methods_supported = [...config.introspectionEndpointAuthMethods];
    ctx.body.introspection_endpoint_auth_signing_alg_values_supported = config.introspectionEndpointAuthSigningAlgValues;
  }

  if (features.jwtIntrospection.enabled) {
    ctx.body.introspection_signing_alg_values_supported = config.introspectionSigningAlgValues;
  }

  if (features.dPoP.enabled) {
    ctx.body.dpop_signing_alg_values_supported = config.dPoPSigningAlgValues;
  }

  if (features.revocation.enabled) {
    ctx.body.revocation_endpoint = ctx.oidc.urlFor('revocation');
    ctx.body.revocation_endpoint_auth_methods_supported = [...config.revocationEndpointAuthMethods];
    ctx.body.revocation_endpoint_auth_signing_alg_values_supported = config.revocationEndpointAuthSigningAlgValues;
  }

  if (features.encryption.enabled) {
    ctx.body.id_token_encryption_alg_values_supported = config.idTokenEncryptionAlgValues;
    ctx.body.id_token_encryption_enc_values_supported = config.idTokenEncryptionEncValues;

    if (features.jwtUserinfo.enabled) {
      ctx.body.userinfo_encryption_alg_values_supported = config.userinfoEncryptionAlgValues;
      ctx.body.userinfo_encryption_enc_values_supported = config.userinfoEncryptionEncValues;
    }

    if (features.jwtIntrospection.enabled) {
      ctx.body.introspection_encryption_alg_values_supported = config.introspectionEncryptionAlgValues;
      ctx.body.introspection_encryption_enc_values_supported = config.introspectionEncryptionEncValues;
    }

    if (features.jwtResponseModes.enabled) {
      ctx.body.authorization_encryption_alg_values_supported = config.authorizationEncryptionAlgValues;
      ctx.body.authorization_encryption_enc_values_supported = config.authorizationEncryptionEncValues;
    }

    if (requestObjects.request || requestObjects.requestUri) {
      ctx.body.request_object_encryption_alg_values_supported = config.requestObjectEncryptionAlgValues;
      ctx.body.request_object_encryption_enc_values_supported = config.requestObjectEncryptionEncValues;
    }
  }

  if (features.backchannelLogout.enabled) {
    ctx.body.backchannel_logout_supported = true;
    ctx.body.backchannel_logout_session_supported = true;
  }

  if (features.frontchannelLogout.enabled) {
    ctx.body.frontchannel_logout_supported = true;
    ctx.body.frontchannel_logout_session_supported = true;
  }

  if (features.mTLS.enabled && features.mTLS.certificateBoundAccessTokens) {
    ctx.body.tls_client_certificate_bound_access_tokens = true;
  }

  defaults(ctx.body, config.discovery);

  return next();
};
