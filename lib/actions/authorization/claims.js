import { InvalidRequest, OIDCProviderError } from '../../helpers/errors.js';
import instance from '../../helpers/weak_cache.js';
import isJsonObject from '../../helpers/_/is_json_object.js';

/*
 * If claims parameter is provided and supported handles its validation
 * - should not be combined with rt none
 * - should be JSON serialized object with id_token or userinfo properties as objects
 * - claims.userinfo should not be used if authorization result is not access_token
 *
 * Merges requested claims with auth_time as requested if max_age is provided or require_auth_time
 * is configured for the client.
 *
 * Merges requested claims with acr as requested if acr_values is provided
 */
export async function checkClaims(ctx, next) {
  const { params } = ctx.oidc;

  if (params.claims !== undefined) {
    const { claimsParameter, userinfo } = instance(ctx.oidc.provider).features;

    if (claimsParameter.enabled) {
      if (params.response_type === 'none') {
        throw new InvalidRequest('claims parameter should not be combined with response_type none');
      }

      let claims;

      try {
        claims = JSON.parse(params.claims);
      } catch (cause) {
        throw new InvalidRequest('could not parse the claims parameter JSON', undefined, { cause });
      }

      if (!isJsonObject(claims)) {
        throw new InvalidRequest('claims parameter should be a JSON object');
      }

      if (claims.userinfo === undefined && claims.id_token === undefined) {
        throw new InvalidRequest('claims parameter should have userinfo or id_token properties');
      }

      if (claims.userinfo !== undefined && !isJsonObject(claims.userinfo)) {
        throw new InvalidRequest('claims.userinfo should be an object');
      }

      if (claims.id_token !== undefined && !isJsonObject(claims.id_token)) {
        throw new InvalidRequest('claims.id_token should be an object');
      }

      for (const container of ['userinfo', 'id_token']) {
        if (claims[container] !== undefined) {
          for (const value of Object.values(claims[container])) {
            if (value !== null && !isJsonObject(value)) {
              throw new InvalidRequest(`claims.${container} members must be null or objects`);
            }
          }
        }
      }

      if (claims.userinfo && !userinfo.enabled) {
        throw new InvalidRequest('claims.userinfo should not be used since userinfo endpoint is not supported');
      }

      if (params.response_type === 'id_token' && claims.userinfo) {
        throw new InvalidRequest('claims.userinfo should not be used if access_token is not issued');
      }

      await claimsParameter.assertClaimsParameter?.(
        ctx,
        claims,
        ctx.oidc.client,
      );
    }
  }

  return next();
}

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
export function assignClaims(ctx, next) {
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

/*
 * Validates the incoming id_token_hint
 */
export async function checkIdTokenHint(ctx, next) {
  const { oidc } = ctx;
  if (oidc.params.id_token_hint !== undefined) {
    let idTokenHint;
    try {
      idTokenHint = await oidc.provider.IdToken.validate(oidc.params.id_token_hint, oidc.client);
    } catch (cause) {
      if (cause instanceof OIDCProviderError) {
        throw cause;
      }

      throw new InvalidRequest('could not validate id_token_hint', undefined, { cause });
    }
    ctx.oidc.entity('IdTokenHint', idTokenHint);
  }

  return next();
}
