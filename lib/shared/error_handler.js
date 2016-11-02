'use strict';

const instance = require('../helpers/weak_cache');

module.exports = function getErrorHandler(provider, emittedError) {
  return function* apiErrorHandler(next) {
    try {
      yield next;
    } catch (err) {
      const out = {};
      this.status = err.statusCode || 500;

      if (err.expose) {
        Object.assign(out,
          { error: err.message, error_description: err.error_description, scope: err.scope });
      } else {
        Object.assign(out,
          { error: 'server_error', error_description: 'oops something went wrong' });
      }

      // this makes */* requests respond with json (curl, xhr, request libraries), while in
      // browser requests end up rendering the html error instead
      if (this.accepts('json', 'html') === 'html') {
        const renderError = instance(provider).configuration('renderError');
        renderError.call(this, out);
      } else {
        this.body = out;
      }

      if (emittedError) {
        provider.emit(out.error === 'server_error' ? 'server_error' : emittedError, err, this);
      }
    }
  };
};
