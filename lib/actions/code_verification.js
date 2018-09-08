const crypto = require('crypto');

const sessionMiddleware = require('../shared/session');
const paramsMiddleware = require('../shared/assemble_params');
const bodyParser = require('../shared/conditional_body');
const rejectDupes = require('../shared/reject_dupes');
const instance = require('../helpers/weak_cache');
const { InvalidClient, InvalidRequest } = require('../helpers/errors');
const {
  NoCodeError, NotFoundError, ExpiredError, AlreadyUsedError,
} = require('../helpers/re_render_errors');
const formHtml = require('../helpers/user_code_form');
const formPost = require('../response_modes/form_post');
const { normalize } = require('../helpers/user_codes');

const parseBody = bodyParser('application/x-www-form-urlencoded');

module.exports = function getCodeVerification(provider) {
  return {
    get: [
      sessionMiddleware(provider),
      paramsMiddleware(['user_code']),
      async function renderCodeVerification(ctx, next) {
        const {
          userCodeInputSource,
          features: { deviceFlow: { charset } },
        } = instance(provider).configuration();

        // TODO: generic xsrf middleware to remove this
        const secret = crypto.randomBytes(24).toString('hex');
        ctx.oidc.session.device = { secret };

        const action = provider.pathFor('code_verification');
        if (ctx.oidc.params.user_code) {
          await formPost(ctx, action, {
            xsrf: secret,
            user_code: ctx.oidc.params.user_code,
          });
        } else {
          await userCodeInputSource(ctx, formHtml.input(action, secret, undefined, charset));
        }

        await next();
      },
    ],
    post: [
      sessionMiddleware(provider),
      parseBody,
      paramsMiddleware(['xsrf', 'user_code', 'confirm']),
      rejectDupes,

      async function codeVerificationCSRF(ctx, next) {
        if (!ctx.oidc.session.device) {
          throw new InvalidRequest('could not find device form details');
        }
        if (ctx.oidc.session.device.secret !== ctx.oidc.params.xsrf) {
          throw new InvalidRequest('xsrf token invalid');
        }
        await next();
      },

      async function loadDeviceCodeByUserInput(ctx, next) {
        const { userCodeConfirmSource } = instance(provider).configuration();
        const { user_code: userCode, confirm } = ctx.oidc.params;

        if (!userCode) {
          throw new NoCodeError();
        }

        const code = await provider.DeviceCode.findByUserCode(
          normalize(userCode),
          { ignoreExpiration: true },
        );

        if (!code) {
          throw new NotFoundError(userCode);
        }

        if (code.isExpired) {
          throw new ExpiredError(userCode);
        }
        if (code.error || code.accountId) {
          throw new AlreadyUsedError(userCode);
        }

        ctx.oidc.entity('DeviceCode', code);

        if (!confirm) {
          const client = await provider.Client.find(code.clientId);
          if (!client) {
            throw new InvalidClient();
          }
          ctx.oidc.entity('Client', client);

          const action = provider.pathFor('code_verification');
          await userCodeConfirmSource(
            ctx,
            formHtml.confirm(action, ctx.oidc.session.device.secret, userCode),
            client,
            code.deviceInfo,
          );
          return;
        }

        await next();
      },

      async function cleanup(ctx, next) {
        ctx.oidc.session.device = undefined;
        await next();
      },
    ],
  };
};
