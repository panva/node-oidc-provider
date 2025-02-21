import presence from '../../helpers/validate_presence.js';

/*
 * Validates presence of redirect_uri and conditionally nonce if specific implicit or hybrid flow
 * are used.
 * Validates that openid scope is present is OpenID Connect specific parameters are provided.
 */
export default function oidcRequired(ctx, next) {
  const { params } = ctx.oidc;

  const required = new Set(['redirect_uri']);

  // Check for nonce if implicit or hybrid flow responding with id_token issued by the authorization
  // endpoint
  if (typeof params.response_type === 'string' && params.response_type.includes('id_token')) {
    required.add('nonce');
  }

  // TODO: move this to a new helper function
  if (ctx.oidc.isFapi('1.0 Final')) {
    required.add(ctx.oidc.requestParamScopes.has('openid') ? 'nonce' : 'state');
  }

  presence(ctx, ...required);

  return next();
}
