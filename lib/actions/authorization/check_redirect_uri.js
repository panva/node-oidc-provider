const { InvalidRedirectUri } = require('../../helpers/errors');

/*
 * Checks that provided redirect_uri is allowed in the client configuration
 *
 * @throws: invalid_redirect_uri
 */
module.exports = function checkRedirectUri(ctx, next) {
  if (!ctx.oidc.client.redirectUriAllowed(ctx.oidc.params.redirect_uri)) {
    throw new InvalidRedirectUri();
  } else {
    ctx.oidc.redirectUriCheckPerformed = true;
  }

  return next();
};
