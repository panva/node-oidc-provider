const { RequestNotSupported, RequestUriNotSupported } = require('../../helpers/errors');

/*
 * Rejects registration parameter as not supported.
 *
 * @throws: registration_not_supported
 */
module.exports = function rejectUnsupported(ctx, next) {
  const { requestObjects } = ctx.oidc.provider.configuration('features');
  const { params } = ctx.oidc;

  if (!requestObjects.request && params.request !== undefined && ctx.oidc.route !== 'pushed_authorization_request') {
    throw new RequestNotSupported();
  }

  if (!requestObjects.requestUri && params.request_uri !== undefined) {
    throw new RequestUriNotSupported();
  }

  return next();
};
