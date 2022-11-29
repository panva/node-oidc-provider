import { RequestNotSupported, RequestUriNotSupported } from '../../helpers/errors.js';
import instance from '../../helpers/weak_cache.js';

/*
 * Rejects request and request_uri parameters when not supported.
 *
 * @throws: request_not_supported
 * @throws: request_uri_not_supported
 */
export default function rejectUnsupported(ctx, next) {
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
}
