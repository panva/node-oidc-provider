const merge = require('../../helpers/_/merge');
const instance = require('../../helpers/weak_cache');

/*
 * Merges requested claims with auth_time as requested if max_age is provided or require_auth_time
 * is configured for the client.
 *
 * Merges requested claims with acr as requested if acr_values is provided
 */
module.exports = function assignClaims(ctx, next) {
  const { params } = ctx.oidc;

  if (params.claims !== undefined && instance(ctx.oidc.provider).configuration('features.claimsParameter.enabled')) {
    ctx.oidc.claims = JSON.parse(params.claims);
  }

  if (params.max_age !== undefined || ctx.oidc.client.requireAuthTime || ctx.oidc.prompts.has('login')) {
    merge(ctx.oidc.claims, { id_token: { auth_time: { essential: true } } });
  }

  const acrValues = params.acr_values;

  if (acrValues) {
    merge(ctx.oidc.claims, { id_token: { acr: { values: acrValues.split(' ') } } });
  }

  return next();
};
