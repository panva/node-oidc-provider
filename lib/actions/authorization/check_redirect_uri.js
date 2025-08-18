import { InvalidRedirectUri, InvalidRequest } from '../../helpers/errors.js';
import instance from '../../helpers/weak_cache.js';

function allowUnregisteredUri(ctx) {
  const { pushedAuthorizationRequests } = instance(ctx.oidc.provider).features;

  return (ctx.oidc.route === 'pushed_authorization_request' || ('PushedAuthorizationRequest' in ctx.oidc.entities))
    && pushedAuthorizationRequests.allowUnregisteredRedirectUris
    && ctx.oidc.client.sectorIdentifierUri === undefined
    && ctx.oidc.client.clientAuthMethod !== 'none';
}

function validateUnregisteredUri(ctx) {
  const { redirectUris: validator } = ctx.oidc.provider.Client.Schema.prototype;

  validator.call({
    ...ctx.oidc.client.metadata(),
    invalidate(detail) {
      throw new InvalidRequest(detail.replace('redirect_uris', 'redirect_uri'));
    },
  }, [ctx.oidc.params.redirect_uri]);

  return true;
}

/*
 * Checks that provided redirect_uri is allowed
 */
export default function checkRedirectUri(ctx, next) {
  if (!ctx.oidc.client.redirectUriAllowed(ctx.oidc.params.redirect_uri)) {
    if (!allowUnregisteredUri(ctx)) {
      throw new InvalidRedirectUri();
    }

    validateUnregisteredUri(ctx);
  }

  ctx.oidc.redirectUriCheckPerformed = true;

  return next();
}
