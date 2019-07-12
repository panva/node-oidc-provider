const crypto = require('crypto');

const Debug = require('debug');

const instance = require('../helpers/weak_cache');
const formHtml = require('../helpers/user_code_form');
const { ReRenderError } = require('../helpers/re_render_errors');
const errOut = require('../helpers/err_out');

const debug = new Debug('oidc-provider:error');
const serverError = new Debug('oidc-provider:server_error');
const serverErrorTrace = new Debug('oidc-provider:server_error:trace');

const userInputRoutes = new Set(['code_verification', 'device_resume']);

module.exports = function getErrorHandler(provider, eventName) {
  return async function errorHandler(ctx, next) {
    const {
      features: { deviceFlow: { charset, userCodeInputSource } },
    } = instance(provider).configuration();

    try {
      await next();
    } catch (err) {
      const out = errOut(err);
      ctx.status = err.statusCode || 500;

      if (err.expose && !(err instanceof ReRenderError)) {
        debug('uid=%s path=%s method=%s error=%o detail=%s', ctx.oidc && ctx.oidc.uid, ctx.path, ctx.method, out, err.error_detail);
      } else if (!(err instanceof ReRenderError)) {
        serverError('uid=%s path=%s method=%s error=%o', ctx.oidc && ctx.oidc.uid, ctx.path, ctx.method, err);
        serverErrorTrace(err);
      }

      if (ctx.oidc && ctx.oidc.session && userInputRoutes.has(ctx.oidc.route)) {
        const secret = crypto.randomBytes(24).toString('hex');
        ctx.oidc.session.state = { secret };

        await userCodeInputSource(ctx, formHtml.input(provider.pathFor('code_verification'), secret, err.userCode, charset), out, err);
        if (err instanceof ReRenderError) { // render without emit
          return;
        }
      } else if (ctx.accepts('json', 'html') === 'html') {
        // this ^^ makes */* requests respond with json (curl, xhr, request libraries), while in
        // browser requests end up rendering the html error instead
        const renderError = instance(provider).configuration('renderError');
        await renderError(ctx, out, err);
      } else {
        ctx.body = out;
      }

      if (out.error === 'server_error') {
        provider.emit('server_error', ctx, err);
      } else if (eventName) {
        provider.emit(eventName, ctx, err);
      }
    }
  };
};
