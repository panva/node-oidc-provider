const { RequestNotSupported, RequestUriNotSupported } = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');

/*
 * Rejects registration parameter as not supported.
 *
 * @throws: registration_not_supported
 */
module.exports = function rejectUnsupported(ctx, next) {
  const { requestObjects } = instance(ctx.oidc.provider).configuration('features');
  const { params } = ctx.oidc;

  if (!requestObjects.request && params.request !== undefined) {
    throw new RequestNotSupported();
  }

  if (!requestObjects.requestUri && params.request_uri !== undefined) {
    throw new RequestUriNotSupported();
  }

  return next();
};
