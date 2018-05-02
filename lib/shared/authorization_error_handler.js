const { RedirectUriMismatchError } = require('../helpers/errors');
const instance = require('../helpers/weak_cache');
const Debug = require('debug');

const debug = new Debug('oidc-provider:authentication:error');
const serverError = new Debug('oidc-provider:server_error');
const serverErrorTrace = new Debug('oidc-provider:server_error:trace');
const rendered = ['invalid_client', 'redirect_uri_mismatch'];

module.exports = (provider) => {
  function getOutAndEmit(ctx, err, state) {
    const out = err.expose ?
      { error: err.message, error_description: err.error_description } :
      { error: 'server_error', error_description: 'oops something went wrong' };

    if (state !== undefined) out.state = state;

    if (err.expose) {
      provider.emit('authorization.error', err, ctx);
      debug('uuid=%s %o', ctx.oidc.uuid, out);
    } else {
      provider.emit('server_error', err, ctx);
      serverError('uuid=%s path=%s method=%s error=%o', ctx.oidc.uuid, ctx.path, ctx.method, err);
      serverErrorTrace(err);
    }

    return out;
  }

  return async function authorizationErrorHandler(ctx, next) {
    try {
      await next();
    } catch (caught) {
      let err = caught;
      ctx.status = err.statusCode || 500;

      const { params = (ctx.method === 'POST' ? ctx.oidc.body : ctx.query) || {} } = ctx.oidc;

      // TODO: don't swallow the original caught, still emit it.
      if (ctx.oidc.client && params.redirect_uri && !ctx.oidc.redirectUriCheckPerformed) {
        if (!ctx.oidc.client.redirectUriAllowed(params.redirect_uri)) {
          getOutAndEmit(ctx, caught, params.state);
          err = new RedirectUriMismatchError();
          ctx.status = err.statusCode;
        }
      }

      const out = getOutAndEmit(ctx, err, params.state);

      // in case redirect_uri/client could not be verified no redirect should happen, render instead
      if (!params.client_id || !params.redirect_uri || rendered.includes(err.message)) {
        const renderError = instance(provider).configuration('renderError');
        await renderError(ctx, out);
        return;
      }

      const handler = instance(provider).responseModes.get(params.response_mode || 'query');
      await handler(ctx, params.redirect_uri, out);
    }
  };
};
