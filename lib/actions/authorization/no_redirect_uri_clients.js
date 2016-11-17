'use strict';

/*
 * If no redirect_uri is provided and client only pre-registered one unique value it's assumed
 * to be the requested redirect_uri and used as if it was explicitly provided;
 */
module.exports = async function noRedirectUriClients(ctx, next) {
  const oidc = ctx.oidc;

  if (oidc.params.redirect_uri === undefined && oidc.client.redirectUris.length === 1) {
    oidc.params.redirect_uri = oidc.client.redirectUris[0];
  }

  await next();
};
