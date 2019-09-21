const instance = require('../../helpers/weak_cache');
const presence = require('../../helpers/validate_presence');

/*
 * Validates presence of redirect_uri and conditionally nonce if specific implicit or hybrid flow
 * are used.
 * Validates that openid scope is present is OpenID Connect specific parameters are provided.
 *
 * @throws: invalid_request
 */
module.exports = function oidcRequired(ctx, next) {
  const { params } = ctx.oidc;

  const required = new Set(['redirect_uri']);

  // Check for nonce if implicit or hybrid flow responding with id_token issued by the authorization
  // endpoint
  if (typeof params.response_type === 'string' && params.response_type.includes('id_token')) {
    required.add('nonce');
  }

  // TODO: add the following once https://bitbucket.org/openid/fapi/issues/270/jarm-fapi-rw-openid-client-session-binding
  // is resolved and the FAPI suite updated
  // else if (instance(ctx.oidc.provider).configuration('features.fapiRW.enabled')) {
  //   required.add('state');
  // }

  if (instance(ctx.oidc.provider).configuration('features.fapiRW.enabled')) {
    required.add(ctx.oidc.requestParamScopes.has('openid') ? 'nonce' : 'state');
  }

  presence(ctx, ...required);

  return next();
};
