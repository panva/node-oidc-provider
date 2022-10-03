const { InvalidRedirectUri, WebMessageUriMismatch } = require('../../helpers/errors');

/*
 * Remaps the Pushed Authorization Request Endpoint errors thrown in downstream middlewares.
 *
 * @throws: invalid_request
 */
module.exports = async function requestObjectRemapErrors(ctx, next) {
  return next().catch((err) => {
    if (err instanceof InvalidRedirectUri || err instanceof WebMessageUriMismatch) {
      Object.assign(err, {
        message: 'invalid_request',
        error: 'invalid_request',
      });
    }

    throw err;
  });
};
