const { RedirectUriMismatch } = require('../../helpers/errors');

/*
 * Checks that provided redirect_uri is whitelisted by the client configuration
 *
 * @throws: redirect_uri_mismatch
 */
module.exports = async function checkRedirectUri(ctx, next) {
  ctx.oidc.redirectUriCheckPerformed = true;

  if (!ctx.oidc.client.redirectUriAllowed(ctx.oidc.params.redirect_uri)) {
    ctx.throw(new RedirectUriMismatch());
  }

  await next();
};
