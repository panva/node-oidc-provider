import appendWWWAuthenticate from '../helpers/append_www_authenticate.js';
import instance from '../helpers/weak_cache.js';
import { InvalidDpopProof, UseDpopNonce } from '../helpers/errors.js';
import { NoAccessTokenProvided } from '../helpers/oidc_context.js';

export default function getSetWWWAuthenticateHeader({ tokenProperty = 'accessToken', includeScope = true, dpop } = {}) {
  return async function setWWWAuthenticateHeader(ctx, next) {
    try {
      await next();
    } catch (err) {
      if (!err.expose || (dpop === false && err.statusCode !== 401)) throw err;

      const conf = instance(ctx.oidc.provider);
      const dpopEnabled = dpop !== false && conf.features.dPoP.enabled;
      const scope = includeScope ? err.scope : undefined;
      const algs = dpopEnabled ? conf.configuration.dPoPSigningAlgValues.join(' ') : undefined;

      if (err instanceof NoAccessTokenProvided) {
        appendWWWAuthenticate(ctx, 'Bearer', { realm: ctx.oidc.issuer, scope });
        if (dpopEnabled) {
          appendWWWAuthenticate(ctx, 'DPoP', { realm: ctx.oidc.issuer, scope, algs });
        }

        throw err;
      }

      let scheme = 'Bearer';

      if (dpopEnabled) {
        if (/dpop/i.test(err.error_description) || ctx.oidc[tokenProperty]?.jkt || ctx.get('DPoP')) {
          scheme = 'DPoP';
        }

        // DPoP proof validation errors are not 401 by default, make them so
        if (err instanceof InvalidDpopProof || err instanceof UseDpopNonce) {
          // eslint-disable-next-line no-multi-assign
          err.status = err.statusCode = 401;
        }
      }

      appendWWWAuthenticate(ctx, scheme, {
        realm: ctx.oidc.issuer,
        error: err.error ?? err.message,
        error_description: err.error_description,
        scope,
        ...(scheme === 'DPoP' ? { algs } : undefined),
      });

      throw err;
    }
  };
}
