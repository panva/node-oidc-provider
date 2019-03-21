/*
 * If no redirect_uri is provided and client only pre-registered one unique value it is assumed
 * to be the requested redirect_uri and used as if it was explicitly provided;
 */
module.exports = function oneRedirectUriClients(ctx, next) {
  const { params, client } = ctx.oidc;

  if (params.redirect_uri === undefined && client.redirectUris.length === 1) {
    ctx.oidc.redirectUriCheckPerformed = true;
    [params.redirect_uri] = client.redirectUris;
  }

  return next();
};
