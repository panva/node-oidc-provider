import { InvalidRequest } from '../../helpers/errors.js';
import dpopValidate, { DPOP_OK_WINDOW } from '../../helpers/validate_dpop.js';
import epochTime from '../../helpers/epoch_time.js';
import instance from '../../helpers/weak_cache.js';

/*
 * Validates dpop_jkt equals the used DPoP proof thumbprint
 * when provided, otherwise defaults dpop_jkt to it.
 */
export default async function checkDpopJkt(ctx, next) {
  const { params } = ctx.oidc;

  const dPoP = await dpopValidate(ctx);
  if (dPoP) {
    const { allowReplay } = instance(ctx.oidc.provider).features.dPoP;
    if (!allowReplay) {
      const { ReplayDetection } = ctx.oidc.provider;
      const unique = await ReplayDetection.unique(
        ctx.oidc.client.clientId,
        dPoP.jti,
        epochTime() + DPOP_OK_WINDOW,
      );

      ctx.assert(unique, new InvalidRequest('DPoP proof JWT Replay detected'));
    }

    if (params.dpop_jkt && params.dpop_jkt !== dPoP.thumbprint) {
      throw new InvalidRequest('DPoP proof key thumbprint does not match dpop_jkt');
    } else if (!params.dpop_jkt) {
      params.dpop_jkt = dPoP.thumbprint;
    }
  }

  return next();
}
