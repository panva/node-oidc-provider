const { InvalidRedirectUri } = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');

const PAR = 'pushed_authorization_request';
const AUTH = 'authorization';

/*
 * Checks that provided redirect_uri is allowed in the client configuration
 *
 * If pushed authorization requests enabled with dynamic redirect URIs,
 * checks redirect URI has same domain as registered URI
 *
 * @throws: invalid_redirect_uri
 */
module.exports = function checkRedirectUri(ctx, next) {
  const {
    pushedAuthorizationRequests: {
      enabled, allowDynamicRedirectUris,
    },
  } = instance(ctx.oidc.provider).configuration('features');

  const isPAR = ctx.oidc.route === PAR
    || (ctx.oidc.route === AUTH && ctx.oidc.entities.PushedAuthorizationRequest);

  const isDomainRedirectAllowed = enabled && allowDynamicRedirectUris
    && isPAR;

  if (!ctx.oidc.client.redirectUriAllowed(ctx.oidc.params.redirect_uri, isDomainRedirectAllowed)) {
    throw new InvalidRedirectUri();
  } else {
    ctx.oidc.redirectUriCheckPerformed = true;
  }

  return next();
};
