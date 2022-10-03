const { RequestNotSupported, RequestUriNotSupported } = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');

/*
 * Rejects request and request_uri parameters when not supported.
 *
 * @throws: request_not_supported
 * @throws: request_uri_not_supported
 */
module.exports = function rejectUnsupported(ctx, next) {
  const { requestObjects, pushedAuthorizationRequests } = instance(ctx.oidc.provider).configuration('features');
  const { params } = ctx.oidc;

  if (
    !requestObjects.request
    && params.request !== undefined
    && (ctx.oidc.route !== 'pushed_authorization_request' && ctx.oidc.route !== 'backchannel_authentication')
  ) {
    throw new RequestNotSupported();
  }

  if (
    (!requestObjects.requestUri && !pushedAuthorizationRequests.enabled)
    && params.request_uri !== undefined
  ) {
    throw new RequestUriNotSupported();
  }

  return next();
};
