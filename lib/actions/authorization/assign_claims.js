const { merge } = require('lodash');

const instance = require('../../helpers/weak_cache');

/*
 * If claims parameter is provided and supported handles it's validation
 * - should not be combined with rt none
 * - should be JSON serialized object with id_token or userinfo properties as objects
 * - claims.userinfo should not be used if authorization result is not access_token
 *
 * Merges requested claims with auth_time as requested if max_age is provided or require_auth_time
 * is configured for the client.
 *
 * Merges requested claims with acr as requested if acr_values is provided
 *
 * @throws: invalid_request
 */
module.exports = provider => async function assignClaims(ctx, next) {
  const { params } = ctx.oidc;

  if (params.claims !== undefined && instance(provider).configuration('features.claimsParameter')) {
    ctx.oidc.claims = JSON.parse(params.claims);
  }

  if (params.max_age || ctx.oidc.client.requireAuthTime || ctx.oidc.prompts.includes('login')) {
    merge(ctx.oidc.claims, { id_token: { auth_time: { essential: true } } });
  }

  const acrValues = params.acr_values;

  if (acrValues) {
    merge(ctx.oidc.claims, { id_token: { acr: { values: acrValues.split(' ') } } });
  }

  await next();
};
