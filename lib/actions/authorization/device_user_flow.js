import Params from '../../helpers/params.js';
import {
  NotFoundError, ExpiredError, AlreadyUsedError,
} from '../../helpers/re_render_errors.js';

export default async function deviceUserFlow(allowList, ctx, next) {
  if (ctx.oidc.route === 'device_resume') {
    const code = await ctx.oidc.provider.DeviceCode.find(
      ctx.oidc.entities.Interaction.deviceCode,
      { ignoreExpiration: true, ignoreSessionBinding: true },
    );

    if (!code) {
      throw new NotFoundError();
    }

    if (code.isExpired) {
      throw new ExpiredError();
    }

    if (code.error || code.accountId) {
      throw new AlreadyUsedError();
    }

    ctx.oidc.entity('DeviceCode', code);
  } else {
    ctx.oidc.params = new (Params(allowList))(ctx.oidc.deviceCode.params);
  }

  await next();
}
