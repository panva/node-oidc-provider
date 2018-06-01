const instance = require('../helpers/weak_cache');
const Debug = require('debug');

const debug = new Debug('oidc-provider:error');
const serverError = new Debug('oidc-provider:server_error');
const serverErrorTrace = new Debug('oidc-provider:server_error:trace');

module.exports = function getErrorHandler(provider, eventName) {
  return async function apiErrorHandler(ctx, next) {
    try {
      await next();
    } catch (err) {
      const out = {};
      ctx.status = err.statusCode || 500;

      if (err.expose) {
        Object.assign(
          out,
          { error: err.message, error_description: err.error_description },
        );

        if (err.scope) out.scope = err.scope;

        debug('uuid=%s path=%s method=%s error=%o detail=%s', ctx.oidc.uuid, ctx.path, ctx.method, out, err.error_detail);
      } else {
        serverError('uuid=%s path=%s method=%s error=%o', ctx.oidc.uuid, ctx.path, ctx.method, err);
        serverErrorTrace(err);
        Object.assign(
          out,
          { error: 'server_error', error_description: 'oops something went wrong' },
        );
      }

      // this makes */* requests respond with json (curl, xhr, request libraries), while in
      // browser requests end up rendering the html error instead
      if (ctx.accepts('json', 'html') === 'html') {
        const renderError = instance(provider).configuration('renderError');
        await renderError(ctx, out, err);
      } else {
        ctx.body = out;
      }

      if (out.error === 'server_error') {
        provider.emit('server_error', err, ctx);
      } else if (eventName) {
        provider.emit(eventName, err, ctx);
      }
    }
  };
};
