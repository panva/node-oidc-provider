const { RequestNotSupported, RequestUriNotSupported } = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');

/*
 * Rejects registration parameter as not supported.
 *
 * @throws: registration_not_supported
 */
module.exports = function rejectUnsupported(ctx, next) {
  const { request, requestUri } = instance(ctx.oidc.provider).configuration('features');
  const { params } = ctx.oidc;

  if (!request.enabled && params.request !== undefined) {
    throw new RequestNotSupported();
  }

  if (!requestUri.enabled && params.request_uri !== undefined) {
    throw new RequestUriNotSupported();
  }

  return next();
};
