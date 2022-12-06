/* eslint-disable max-len */

import defaults from '../helpers/_/defaults.js';
import instance from '../helpers/weak_cache.js';

export default function discovery(ctx, next) {
  const config = instance(ctx.oidc.provider).configuration();
  const { features } = config;

  ctx.body = {
    acr_values_supported: config.acrValues.size ? [...config.acrValues] : undefined,
    authorization_endpoint: ctx.oidc.urlFor('authorization'),
    device_authorization_endpoint: features.deviceFlow.enabled
      ? ctx.oidc.urlFor('device_authorization')
      : undefined,
    claims_parameter_supported: features.claimsParameter.enabled,
    claims_supported: [...config.claimsSupported],
    code_challenge_methods_supported: config.pkce.methods,
    end_session_endpoint: features.rpInitiatedLogout.enabled
      ? ctx.oidc.urlFor('end_session')
      : undefined,
    grant_types_supported: [...config.grantTypes],
    issuer: ctx.oidc.issuer,
    jwks_uri: ctx.oidc.urlFor('jwks'),
    registration_endpoint: features.registration.enabled
      ? ctx.oidc.urlFor('registration')
      : undefined,
    authorization_response_iss_parameter_supported: true,
    response_modes_supported: ['form_post', 'fragment', 'query'],
    response_types_supported: config.responseTypes,
    scopes_supported: [...config.scopes],
    subject_types_supported: [...config.subjectTypes],
    token_endpoint_auth_methods_supported: [...config.clientAuthMethods],
    token_endpoint_auth_signing_alg_values_supported: config.clientAuthSigningAlgValues,
    token_endpoint: ctx.oidc.urlFor('token'),
  };

  const { pushedAuthorizationRequests, requestObjects } = features;

  ctx.body.id_token_signing_alg_values_supported = config.idTokenSigningAlgValues;
  if (features.encryption.enabled) {
    ctx.body.id_token_encryption_alg_values_supported = config.idTokenEncryptionAlgValues;
    ctx.body.id_token_encryption_enc_values_supported = config.idTokenEncryptionEncValues;
  }

  if (pushedAuthorizationRequests.enabled) {
    ctx.body.pushed_authorization_request_endpoint = ctx.oidc.urlFor(
      'pushed_authorization_request',
    );
    ctx.body.require_pushed_authorization_requests = pushedAuthorizationRequests.requirePushedAuthorizationRequests ? true : undefined;
  }

  ctx.body.request_parameter_supported = requestObjects.request;
  ctx.body.request_uri_parameter_supported = requestObjects.requestUri;
  if (requestObjects.request || requestObjects.requestUri) {
    ctx.body.request_object_signing_alg_values_supported = config.requestObjectSigningAlgValues;
    ctx.body.require_request_uri_registration = requestObjects.requestUri && requestObjects.requireUriRegistration ? true : undefined;
    ctx.body.require_signed_request_object = requestObjects.requireSignedRequestObject
      ? true
      : undefined;

    if (features.encryption.enabled) {
      ctx.body.request_object_encryption_alg_values_supported = config.requestObjectEncryptionAlgValues;
      ctx.body.request_object_encryption_enc_values_supported = config.requestObjectEncryptionEncValues;
    }
  }

  if (features.userinfo.enabled) {
    ctx.body.userinfo_endpoint = ctx.oidc.urlFor('userinfo');
    if (features.jwtUserinfo.enabled) {
      ctx.body.userinfo_signing_alg_values_supported = config.userinfoSigningAlgValues;
      if (features.encryption.enabled) {
        ctx.body.userinfo_encryption_alg_values_supported = config.userinfoEncryptionAlgValues;
        ctx.body.userinfo_encryption_enc_values_supported = config.userinfoEncryptionEncValues;
      }
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

    if (features.encryption.enabled) {
      ctx.body.authorization_encryption_alg_values_supported = config.authorizationEncryptionAlgValues;
      ctx.body.authorization_encryption_enc_values_supported = config.authorizationEncryptionEncValues;
    }
  }

  if (features.introspection.enabled) {
    ctx.body.introspection_endpoint = ctx.oidc.urlFor('introspection');
  }

  if (features.jwtIntrospection.enabled) {
    ctx.body.introspection_signing_alg_values_supported = config.introspectionSigningAlgValues;
    if (features.encryption.enabled) {
      ctx.body.introspection_encryption_alg_values_supported = config.introspectionEncryptionAlgValues;
      ctx.body.introspection_encryption_enc_values_supported = config.introspectionEncryptionEncValues;
    }
  }

  if (features.dPoP.enabled) {
    ctx.body.dpop_signing_alg_values_supported = config.dPoPSigningAlgValues;
  }

  if (features.revocation.enabled) {
    ctx.body.revocation_endpoint = ctx.oidc.urlFor('revocation');
  }

  if (features.backchannelLogout.enabled) {
    ctx.body.backchannel_logout_supported = true;
    ctx.body.backchannel_logout_session_supported = true;
  }

  if (features.mTLS.enabled && features.mTLS.certificateBoundAccessTokens) {
    ctx.body.tls_client_certificate_bound_access_tokens = true;
  }

  if (features.ciba.enabled) {
    ctx.body.backchannel_authentication_endpoint = ctx.oidc.urlFor('backchannel_authentication');
    ctx.body.backchannel_token_delivery_modes_supported = [...features.ciba.deliveryModes];
    ctx.body.backchannel_user_code_parameter_supported = true;
    ctx.body.backchannel_authentication_request_signing_alg_values_supported = requestObjects.request
      ? config.requestObjectSigningAlgValues.filter((alg) => !alg.startsWith('HS'))
      : undefined;
  }

  defaults(ctx.body, config.discovery);

  return next();
}
