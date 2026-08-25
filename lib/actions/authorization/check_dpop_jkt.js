import { InvalidRequest } from '../../helpers/errors.js';
import dpopValidate, { checkDpopReplay } from '../../helpers/validate_dpop.js';

/*
 * Validates dpop_jkt equals the used DPoP proof thumbprint
 * when provided, otherwise defaults dpop_jkt to it.
 */
export default async function checkDpopJkt(ctx, next) {
  const { params } = ctx.oidc;

  const dPoP = await dpopValidate(ctx);
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
