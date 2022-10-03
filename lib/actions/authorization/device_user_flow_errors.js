const { AccessDenied } = require('../../helpers/errors');
const {
  ReRenderError, AbortedError,
} = require('../../helpers/re_render_errors');
const errOut = require('../../helpers/err_out');

module.exports = async function deviceUserFlowErrors(ctx, next) {
  try {
    await next();
  } catch (err) {
    if (!(err instanceof ReRenderError)) {
      const out = errOut(err);

      let code = ctx.oidc.deviceCode;

      if (!code && ctx.oidc.entities.Interaction && ctx.oidc.entities.Interaction.deviceCode) {
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
};
