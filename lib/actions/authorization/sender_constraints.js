import { boolean } from '../../helpers/configuration_result.js';
import { InvalidRequest } from '../../helpers/errors.js';
import checkFormat from '../../helpers/pkce_format.js';
import instance from '../../helpers/weak_cache.js';
import dpopValidate, { checkDpopReplay } from '../../helpers/validate_dpop.js';

/*
 * - assign default code_challenge_method if a code_challenge is provided
 * - check presence of code code_challenge if code_challenge_method is provided
 * - enforce PKCE use for native clients using hybrid or code flow
 */
export function checkPKCE(ctx, next) {
  const { params } = ctx.oidc;
  const { pkce } = instance(ctx.oidc.provider).configuration;

  if (!params.code_challenge_method && params.code_challenge) {
    throw new InvalidRequest('code_challenge_method must be provided');
  }

  if (params.code_challenge_method) {
    if (params.code_challenge_method !== 'S256') {
      throw new InvalidRequest('not supported value of code_challenge_method');
    }

    if (!params.code_challenge) {
      throw new InvalidRequest('code_challenge must be provided with code_challenge_method');
    }
  }

  if (params.response_type.includes('code')) {
    if (!params.code_challenge) {
      if (boolean(pkce.required(ctx, ctx.oidc.client), 'pkce.required')) {
        throw new InvalidRequest('Authorization Server policy requires PKCE to be used for this request');
      }
    }
  }

  if (params.code_challenge !== undefined) {
    checkFormat(params.code_challenge, 'code_challenge');
  }

  return next();
}

/*
 * Validates dpop_jkt equals the used DPoP proof thumbprint
 * when provided, otherwise defaults dpop_jkt to it.
 */
export async function checkDpopJkt(ctx, next) {
  const { params } = ctx.oidc;

  const dPoP = await dpopValidate(ctx.oidc.provider, ctx);
  if (dPoP) {
    await checkDpopReplay(ctx.oidc.provider, ctx, dPoP, ctx.oidc.client.clientId, InvalidRequest);

    if (params.dpop_jkt && params.dpop_jkt !== dPoP.thumbprint) {
      throw new InvalidRequest('DPoP proof key thumbprint does not match dpop_jkt');
    } else if (!params.dpop_jkt) {
      params.dpop_jkt = dPoP.thumbprint;
    }
  }

  return next();
}
