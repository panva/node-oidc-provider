import { InvalidRequestUri, RequestUriNotSupported } from '../../helpers/errors.js';
import instance from '../../helpers/weak_cache.js';
import { PUSHED_REQUEST_URN } from '../../consts/index.js';

import rejectRequestAndUri from './reject_request_and_uri.js';

/*
 * Validates request_uri is a PAR one when PAR is enabled and loads it. Throws
 */
export default async function loadPushedAuthorizationRequest(ctx, next) {
  const { pushedAuthorizationRequests } = instance(ctx.oidc.provider).features;
  const { params, provider: { PushedAuthorizationRequest } } = ctx.oidc;

  rejectRequestAndUri(ctx, () => {});

  if (params.request_uri !== undefined) {
    if (pushedAuthorizationRequests.enabled && params.request_uri.startsWith(PUSHED_REQUEST_URN)) {
      if (!URL.canParse(params.request_uri)) {
        throw new InvalidRequestUri('invalid request_uri');
      }
      const [, id] = params.request_uri.split(PUSHED_REQUEST_URN);
      const pushedAuthorizationRequest = await PushedAuthorizationRequest.find(id, {
        ignoreExpiration: true,
      });
      if (!pushedAuthorizationRequest?.isValid) {
        throw new InvalidRequestUri('request_uri is invalid, expired, or was already used');
      }
      ctx.oidc.entity('PushedAuthorizationRequest', pushedAuthorizationRequest);
      params.request = pushedAuthorizationRequest.request;
    } else {
      throw new RequestUriNotSupported();
    }
  }

  return next();
}
