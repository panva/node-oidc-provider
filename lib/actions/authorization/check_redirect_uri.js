'use strict';

const errors = require('../../helpers/errors');

/*
 * Checks that provided redirect_uri is whitelisted by the client configuration
 *
 * @throws: redirect_uri_mismatch
 */
module.exports = function* checkRedirectUri(next) {
  this.oidc.redirectUriCheckPerformed = true;
  this.assert(this.oidc.client.redirectUriAllowed(this.oidc.params.redirect_uri),
    new errors.RedirectUriMismatchError());

  yield next;
};
