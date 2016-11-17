'use strict';

const errors = require('../../helpers/errors');

/*
 * Checks that provided redirect_uri is whitelisted by the client configuration
 *
 * @throws: redirect_uri_mismatch
 */
module.exports = async function checkRedirectUri(ctx, next) {
  ctx.oidc.redirectUriCheckPerformed = true;
  ctx.assert(ctx.oidc.client.redirectUriAllowed(ctx.oidc.params.redirect_uri),
    new errors.RedirectUriMismatchError());

  await next();
};
