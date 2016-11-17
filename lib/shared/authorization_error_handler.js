'use strict';

const errors = require('../helpers/errors');
const formPost = require('../shared/form_post');
const redirectUri = require('../helpers/redirect_uri');
const instance = require('../helpers/weak_cache');

module.exports = provider => async function authorizationErrorHandler(ctx, next) { // eslint-disable-line consistent-return, max-len
  try {
    await next();
  } catch (caught) {
    let err = caught;
    const out = {};

    let params;
    params = ctx.oidc.params;
    params = params || (ctx.method === 'POST' ? ctx.request.body : ctx.query) ||
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

    // redirect uri error should render instead of redirect to uri
    if (!params.client_id || !params.redirect_uri ||
      err.message === 'redirect_uri_mismatch' || err.message === 'invalid_client') {
      const renderError = instance(provider).configuration('renderError');
      return renderError.call(ctx, out);
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
