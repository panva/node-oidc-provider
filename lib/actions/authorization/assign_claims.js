import instance from '../../helpers/weak_cache.js';

function assignIdTokenClaim(ctx, claim, value) {
  ctx.oidc.claims ||= {};
  ctx.oidc.claims.id_token ||= {};
  ctx.oidc.claims.id_token[claim] = value;
}

/*
 * Merges requested claims with auth_time as requested if max_age is provided or require_auth_time
 * is configured for the client.
 *
 * Merges requested claims with acr as requested if acr_values is provided
 */
export default function assignClaims(ctx, next) {
  const { params } = ctx.oidc;

  if (params.claims !== undefined && instance(ctx.oidc.provider).features.claimsParameter.enabled) {
    ctx.oidc.claims = JSON.parse(params.claims);
  }

  if (params.max_age !== undefined || ctx.oidc.client.requireAuthTime || ctx.oidc.prompts.has('login')) {
    assignIdTokenClaim(ctx, 'auth_time', { essential: true });
  }

  const acrValues = params.acr_values;

  if (acrValues) {
    assignIdTokenClaim(ctx, 'acr', { values: acrValues.split(' ') });
  }

  return next();
}
