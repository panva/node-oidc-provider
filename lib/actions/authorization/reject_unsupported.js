import { InvalidRequest, RequestNotSupported, RequestUriNotSupported } from '../../helpers/errors.js';
import instance from '../../helpers/weak_cache.js';

/*
 * Rejects request and request_uri parameters when not supported. Also rejects wmrm's relay mode.
 */
export default function rejectUnsupported(ctx, next) {
  const {
    requestObjects,
    pushedAuthorizationRequests,
    webMessageResponseMode,
  } = instance(ctx.oidc.provider).features;
  const { params } = ctx.oidc;

  if (params.request !== undefined && !requestObjects.enabled) {
    throw new RequestNotSupported();
  }

  if (
    params.request_uri !== undefined
    && (ctx.oidc.route !== 'authorization' || !pushedAuthorizationRequests.enabled)
  ) {
    throw new RequestUriNotSupported();
  }

  if (webMessageResponseMode.enabled && params.response_mode?.includes('web_message') && params.web_message_uri) {
    const error = new InvalidRequest('Web Message Response Mode Relay Mode is not supported');
    error.allow_redirect = false;
    throw error;
  }

  return next();
}
