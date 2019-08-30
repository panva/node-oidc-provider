const { OIDCProviderError } = require('../../helpers/errors');

/*
 * Remaps the Request Object Endpoint errors thrown in downstream middlewares
 *
 * @throws: invalid_request_object
 */
module.exports = async function requestObjectRemapErrors(ctx, next) {
  try {
    await next();
  } catch (err) {
    if (err instanceof OIDCProviderError) {
      err.message = 'invalid_request_object';
      err.error = 'invalid_request_object';
    }

    throw err;
  }
};
