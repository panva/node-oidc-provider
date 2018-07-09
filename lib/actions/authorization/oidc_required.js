const presence = require('../../helpers/validate_presence');

/*
 * Validates presence of mandatory OpenID Connect parameters redirect_uri and conditionally nonce if
 * implicit or hybrid flow are used.
 *
 * @throws: invalid_request
 */
module.exports = async function oidcRequired(ctx, next) {
  const { params } = ctx.oidc;

  // Check for nonce if implicit or hybrid flow
  if (params.response_type && params.response_type.includes('token')) {
    presence(ctx, 'redirect_uri', 'nonce');
  } else {
    presence(ctx, 'redirect_uri');
  }


  await next();
};
