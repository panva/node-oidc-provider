const { OIDCProviderError } = require('../../helpers/errors');

/*
 * Remaps the Pushed Authorization Request Endpoint errors thrown in downstream middlewares when
 * coming purely from the JWT Request Object
 *
 * @throws: invalid_request_object
 */
module.exports = async function requestObjectRemapErrors(ctx, next) {
  if (!ctx.oidc.params.request) {
    return next();
  }

  return next().catch((err) => {
    if (err instanceof OIDCProviderError) {
      Object.assign(err, {
        message: 'invalid_request_object',
        error: 'invalid_request_object',
      });
    }

    throw err;
  });
};
