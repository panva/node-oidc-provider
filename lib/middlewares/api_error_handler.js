'use strict';

module.exports = function (provider, emittedError) {
  return function * apiErrorHandler(next) {
    try {
      yield next;
    } catch (err) {

      this.body = {};
      this.status = err.statusCode || 500;

      if (err.expose) {
        Object.assign(this.body, {
          error: err.message,
          error_description: err.error_description,
        });
      } else {
        Object.assign(this.body, {
          error: 'server_error',
          error_description: 'oops something went wrong',
        });
      }

      provider.emit(
        this.body.error === 'server_error' ? 'server_error' : emittedError,
        err, this);
    }
  };
};
