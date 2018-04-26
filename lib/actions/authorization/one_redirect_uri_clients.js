/*
 * If no redirect_uri is provided and client only pre-registered one unique value it's assumed
 * to be the requested redirect_uri and used as if it was explicitly provided;
 */
module.exports = async function oneRedirectUriClients(ctx, next) {
  const { params, client } = ctx.oidc;

  if (params.redirect_uri === undefined && client.redirectUris.length === 1) {
    params.redirect_uri = client.redirectUris[0]; // eslint-disable-line prefer-destructuring
  }

  await next();
};
