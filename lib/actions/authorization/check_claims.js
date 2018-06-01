const { isPlainObject, merge } = require('lodash');
const { InvalidRequest } = require('../../helpers/errors');
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
module.exports = provider => async function checkClaims(ctx, next) {
  const { params } = ctx.oidc;

  if (params.claims !== undefined && instance(provider).configuration('features.claimsParameter')) {
    if (params.response_type === 'none') {
      ctx.throw(new InvalidRequest('claims parameter should not be combined with response_type none'));
    }

    let claims;

    try {
      claims = JSON.parse(params.claims);
    } catch (err) {
      ctx.throw(new InvalidRequest('could not parse the claims parameter JSON'));
    }

    if (!isPlainObject(claims)) {
      ctx.throw(new InvalidRequest('claims parameter should be a JSON object'));
    }

    if (claims.userinfo === undefined && claims.id_token === undefined) {
      ctx.throw(new InvalidRequest('claims parameter should have userinfo or id_token properties'));
    }

    if (claims.userinfo !== undefined && !isPlainObject(claims.userinfo)) {
      ctx.throw(new InvalidRequest('claims.userinfo should be an object'));
    }

    if (claims.id_token !== undefined && !isPlainObject(claims.id_token)) {
      ctx.throw(new InvalidRequest('claims.id_token should be an object'));
    }

    if (params.response_type === 'id_token' && claims.userinfo) {
      ctx.throw(new InvalidRequest('claims.userinfo should not be used if access_token is not issued'));
    }

    ctx.oidc.claims = claims;
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
