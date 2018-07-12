const { RedirectUriMismatch } = require('../../helpers/errors');

/*
 * Checks that provided redirect_uri is whitelisted by the client configuration
 *
 * @throws: redirect_uri_mismatch
 */
module.exports = async function checkRedirectUri(ctx, next) {
  if (!ctx.oidc.client.redirectUriAllowed(ctx.oidc.params.redirect_uri)) {
    throw new RedirectUriMismatch();
  } else {
    ctx.oidc.redirectUriCheckPerformed = true;
  }

  await next();
};
