'use strict';

const errors = require('../helpers/errors');
const formPost = require('../shared/form_post');
const redirectUri = require('../helpers/redirect_uri');
const instance = require('../helpers/weak_cache');
const Debug = require('debug');

const debug = new Debug('oidc-provider:authentication:error');
const serverError = new Debug('oidc-provider:server_error');
const serverErrorTrace = new Debug('oidc-provider:server_error:trace');

module.exports = provider => async function authorizationErrorHandler(ctx, next) { // eslint-disable-line consistent-return, max-len
  try {
    await next();
  } catch (caught) {
    let err = caught;
    const out = {};

    let params;
    params = ctx.oidc.params;
    params = params || (ctx.method === 'POST' ? ctx.oidc.body : ctx.query) ||
      /* istanbul ignore next */ {};

    if (ctx.oidc.client && params.redirect_uri && !ctx.oidc.redirectUriCheckPerformed) {
      if (!ctx.oidc.client.redirectUriAllowed(params.redirect_uri)) {
        err = new errors.RedirectUriMismatchError();
      }
    }

    ctx.status = err.statusCode || 500;

    if (err.expose) {
      Object.assign(out, { error: err.message, error_description: err.error_description });
    } else {
      Object.assign(out,
        { error: 'server_error', error_description: 'oops something went wrong' });
    }

    if (params.state !== undefined) out.state = params.state;

    provider.emit(out.error === 'server_error' ?
      'server_error' : 'authorization.error', err, ctx);

    if (out.error !== 'server_error') {
      debug('uuid=%s %o', ctx.oidc.uuid, out);
    } else {
      serverError('uuid=%s path=%s error=%o', ctx.oidc.uuid, ctx.path, err);
      serverErrorTrace(err);
    }

    // redirect uri error should render instead of redirect to uri
    if (!params.client_id || !params.redirect_uri ||
      err.message === 'redirect_uri_mismatch' || err.message === 'invalid_client') {
      const renderError = instance(provider).configuration('renderError');
      await renderError(ctx, out);
      return;
    }

    // TODO: DRY with respond.js
    if (instance(provider).responseModes.has(params.response_mode)) {
      instance(provider).responseModes.get(params.response_mode)
        .call(ctx, params.redirect_uri, out);
    } else if (params.response_mode === 'form_post') {
      formPost.call(ctx, params.redirect_uri, out);
    } else {
      const uri = redirectUri(params.redirect_uri, out, params.response_mode);
      ctx.redirect(uri);
    }
  }
};
