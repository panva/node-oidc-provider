import { AccessDenied } from '../../helpers/errors.js';
import errOut from '../../helpers/err_out.js';
import {
  ReRenderError, AbortedError,
} from '../../helpers/re_render_errors.js';

export default async function deviceUserFlowErrors(ctx, next) {
  try {
    await next();
  } catch (err) {
    if (!(err instanceof ReRenderError)) {
      const out = errOut(err);

      let code = ctx.oidc.deviceCode;

      if (!code && ctx.oidc.entities.Interaction?.deviceCode) {
        code = await ctx.oidc.provider.DeviceCode.find(
          ctx.oidc.entities.Interaction.deviceCode,
          { ignoreExpiration: true, ignoreSessionBinding: true },
        );
      }

      if (code) {
        Object.assign(code, {
          error: out.error,
          errorDescription: out.error_description,
        });
        await code.save();
        if (err instanceof AccessDenied) {
          throw new AbortedError();
        }
      }
    }

    throw err;
  }
}
