'use strict';

const errors = require('../helpers/errors');
const formPost = require('../helpers/form_post');
const redirectUri = require('../helpers/redirect_uri');

module.exports = function getAuthErrorHandler(provider) {
  return function * authorizationErrorHandler(next) { // eslint-disable-line consistent-return
    try {
      yield next;
    } catch (caught) {
      let err = caught;
      const out = {};

      let params;
      params = this.oidc.params;
      params = params || (this.method === 'POST' ? this.request.body : this.query) ||
        /* istanbul ignore next */ {};

      if (this.oidc.client && params.redirect_uri && !this.oidc.redirectUriCheckPerformed) {
        if (!this.oidc.client.redirectUriAllowed(params.redirect_uri)) {
          err = new errors.RedirectUriMismatchError();
        }
      }

      this.status = err.statusCode || 500;

      if (err.expose) {
        Object.assign(out, {
          error: err.message,
          error_description: err.error_description,
        });
      } else {
        Object.assign(out, {
          error: 'server_error',
          error_description: 'oops something went wrong',
        });
      }

      if (params.state !== undefined) {
        out.state = params.state;
      }

      provider.emit(out.error === 'server_error' ?
        'server_error' : 'authorization.error', err, this);

      // redirect uri error should render instead of redirect to uri
      if (!params.client_id || !params.redirect_uri ||
        err.message === 'redirect_uri_mismatch' || err.message === 'invalid_client') {
        const renderError = provider.configuration('renderError');
        return renderError(this, out);
      }

      if (params.response_mode === 'form_post') {
        return formPost.call(this, params.redirect_uri, out);
      }

      const uri = redirectUri(params.redirect_uri, out, params.response_mode);
      return this.redirect(uri);
    }
  };
};
