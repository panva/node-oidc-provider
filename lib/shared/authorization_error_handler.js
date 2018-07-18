const Debug = require('debug');

const { RedirectUriMismatch, WebMessageUriMismatch } = require('../helpers/errors');
const instance = require('../helpers/weak_cache');
const errOut = require('../helpers/err_out');

const debug = new Debug('oidc-provider:authentication:error');
const serverError = new Debug('oidc-provider:server_error');
const serverErrorTrace = new Debug('oidc-provider:server_error:trace');
const rendered = new Set(['invalid_client', 'redirect_uri_mismatch', 'web_message_uri_mismatch']);

module.exports = (provider) => {
  const AD_ACTA_CHECKS = Object.entries({
    redirect_uri: {
      Err: RedirectUriMismatch,
      method: 'redirectUriAllowed',
      check: 'redirectUriCheckPerformed',
    },
    web_message_uri: {
      Err: WebMessageUriMismatch,
      method: 'webMessageUriAllowed',
      check: 'webMessageUriCheckPerformed',
      flag: 'features.webMessageResponseMode',
    },
  });

  function getOutAndEmit(ctx, err, state) {
    const out = errOut(err, state);

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

  function safe(param) {
    if (param && typeof param === 'string') {
      return param;
    }
    return undefined;
  }

  return async function authorizationErrorHandler(ctx, next) {
    try {
      await next();
    } catch (caught) {
      let err = caught;
      ctx.status = err.statusCode || 500;
      const { oidc } = ctx;

      const { params = (ctx.method === 'POST' ? oidc.body : ctx.query) || {} } = oidc;

      if (!oidc.client && safe(params.client_id)) {
        try {
          oidc.entity('Client', await provider.Client.find(safe(params.client_id)));
        } catch (e) {}
      }

      for (const [param, { // eslint-disable-line no-restricted-syntax
        Err, check, flag, method,
      }] of AD_ACTA_CHECKS) {
        if (
          (!flag || instance(provider).configuration(flag))
          && !(err instanceof Err) && oidc.client
          && safe(params[param]) && !oidc[check]
        ) {
          if (!oidc.client[method](safe(params[param]))) {
            getOutAndEmit(ctx, caught, safe(params.state));
            err = new Err();
            ctx.status = err.statusCode;
            break;
          }
        }
      }

      const out = getOutAndEmit(ctx, err, safe(params.state));

      // in case redirect_uri, client or web_message_uri could not be verified no successful
      // response should happen, render instead
      if (
        !safe(params.client_id)
        || (safe(params.client_id) && !oidc.client)
        || !safe(params.redirect_uri)
        || rendered.has(err.message)
      ) {
        const renderError = instance(provider).configuration('renderError');
        await renderError(ctx, out, err);
        return;
      }

      const handler = instance(provider).responseModes.get(safe(params.response_mode) || 'query');
      await handler(ctx, safe(params.redirect_uri), out);
    }
  };
};
