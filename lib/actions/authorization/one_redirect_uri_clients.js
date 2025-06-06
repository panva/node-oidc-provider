import instance from '../../helpers/weak_cache.js';

/*
 * If no redirect_uri is provided and client only pre-registered one unique value it is assumed
 * to be the requested redirect_uri and used as if it was explicitly provided;
 */
export default function oneRedirectUriClients(ctx, next) {
  if (!instance(ctx.oidc.provider).configuration.allowOmittingSingleRegisteredRedirectUri || ctx.oidc.isFapi('2.0')) {
    return next();
  }

  const { params, client } = ctx.oidc;

  if (params.redirect_uri === undefined && client.redirectUris.length === 1) {
    ctx.oidc.redirectUriCheckPerformed = true;
    [params.redirect_uri] = client.redirectUris;
  }

  return next();
}
