'use strict';

const formPost = require('../helpers/form_post');
const redirectUri = require('../helpers/redirect_uri');

module.exports = function getAuthErrorHandler(provider) {
  return function * authorizationErrorHandler(next) { // eslint-disable-line consistent-return
    try {
      yield next;
    } catch (err) {
      const out = {};
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

      provider.emit(out.error === 'server_error' ?
        'server_error' : 'authorization.error', err, this);

      let params;
      params = this.oidc.params;
      params = params || (this.method === 'POST' ? this.request.body : this.query) ||
        /* istanbul ignore next */ {};

      if (params.state !== undefined) {
        out.state = params.state;
      }

      // redirect uri error should render instead of redirect to uri
      if (err.message === 'redirect_uri_mismatch' || !params.redirect_uri) {
        const renderError = provider.configuration('renderError');
        return renderError.call(this, out);
      }

      if (params.response_mode === 'form_post') {
        return formPost.call(this, params.redirect_uri, out);
      }

      const uri = redirectUri(params.redirect_uri, out, params.response_mode);
      return this.redirect(uri);
    }
  };
};
