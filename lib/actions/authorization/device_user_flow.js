const Debug = require('debug');

const getParams = require('../../helpers/params');
const { InvalidRequest } = require('../../helpers/errors');
const {
  NotFoundError, ReRenderError, ExpiredError, AlreadyUsedError,
} = require('../../helpers/re_render_errors');
const errOut = require('../../helpers/err_out');

const debug = new Debug('oidc-provider:authentication:error');

module.exports = function getDeviceVerification(provider, whitelist) {
  const Params = getParams(whitelist);

  return async function deviceUserFlow(ctx, next) {
    let code;
    try {
      if (ctx.oidc.route === 'device_resume') { // TODO
        code = await provider.DeviceCode.findByUserCode(ctx.params.user_code, {
          ignoreExpiration: true,
        });

        if (!code) {
          throw new NotFoundError();
        }

        if (code.grantId !== ctx.params.grant) {
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

        if (code) ctx.oidc.uuid = code.grantId;
        ctx.oidc.params = new Params(code.params);
      }

      ctx.oidc.uuid = code.grantId;

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
        }

        debug('uuid=%s %o', ctx.oidc.uuid, out);
      }

      throw err;
    }
  };
};
