const debug = require('debug')('oidc-provider:authentication:error');

const Params = require('../../helpers/params');
const { InvalidRequest, AccessDenied } = require('../../helpers/errors');
const {
  NotFoundError, ReRenderError, ExpiredError, AlreadyUsedError, AbortedError,
} = require('../../helpers/re_render_errors');
const errOut = require('../../helpers/err_out');

module.exports = async function deviceUserFlow(whitelist, ctx, next) {
  let code;
  try {
    if (ctx.oidc.route === 'device_resume') { // TODO
      code = await ctx.oidc.provider.DeviceCode.findByUserCode(ctx.params.user_code, {
        ignoreExpiration: true,
      });

      if (!code) {
        throw new NotFoundError();
      }

      if (code.grantId !== ctx.params.uid) {
        throw new InvalidRequest('grantId mismatch');
      }

      if (code.isExpired) {
        throw new ExpiredError();
      }

      if (code.error || code.accountId) {
        throw new AlreadyUsedError();
      }

      ctx.oidc.entity('DeviceCode', code);
    } else {
      code = ctx.oidc.deviceCode;
      if (code) {
        ctx.oidc.uid = code.grantId;
      }

      ctx.oidc.params = new (Params(whitelist))(code.params);
    }

    ctx.oidc.uid = code.grantId;

    await next();
  } catch (err) {
    if (!(err instanceof ReRenderError)) {
      const out = errOut(err);

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
      debug('uid=%s %o', ctx.oidc.uid, out);
    }

    throw err;
  }
};
