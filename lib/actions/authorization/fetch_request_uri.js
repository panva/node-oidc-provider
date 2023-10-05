import { InvalidRequestUri, RequestUriNotSupported } from '../../helpers/errors.js';
import instance from '../../helpers/weak_cache.js';
import { PUSHED_REQUEST_URN } from '../../consts/index.js';

import loadPushedAuthorizationRequest from './load_pushed_authorization_request.js';
import rejectRequestAndUri from './reject_request_and_uri.js';

const allowedSchemes = new Set(['http:', 'https:', 'urn:']);

/*
 * Validates request_uri length, protocol and its presence in client allow list and either uses
 * previously cached response or loads a fresh state. Removes request_uri form the parameters and
 * uses the response body as a value for the request parameter to be validated by a downstream
 * middleware
 *
 * @throws: invalid_request_uri
 * @throws: request_uri_not_allowed
 */
export default async function fetchRequestUri(ctx, next) {
  const { pushedAuthorizationRequests, requestObjects } = instance(ctx.oidc.provider).configuration('features');
  const { params } = ctx.oidc;

  rejectRequestAndUri(ctx, () => {});

  if (params.request_uri !== undefined) {
    let protocol;
    try {
      ({ protocol } = new URL(params.request_uri));
      if (!allowedSchemes.has(protocol)) throw new Error();
    } catch (err) {
      throw new InvalidRequestUri('invalid request_uri scheme');
    }

    let loadedRequestObject = ctx.oidc.entities.PushedAuthorizationRequest;
    if (
      !loadedRequestObject
      && pushedAuthorizationRequests.enabled
      && params.request_uri.startsWith(PUSHED_REQUEST_URN)
    ) {
      loadedRequestObject = await loadPushedAuthorizationRequest(ctx);
    } else if (!loadedRequestObject && !requestObjects.requestUri) {
      throw new RequestUriNotSupported();
    } else if (!loadedRequestObject && ctx.oidc.client.requestUris) {
      if (!ctx.oidc.client.requestUriAllowed(params.request_uri)) {
        throw new InvalidRequestUri('provided request_uri is not allowed');
      }
    }

    if (protocol === 'http:') {
      ctx.oidc.insecureRequestUri = true;
    }

    try {
      if (loadedRequestObject) {
        params.request = loadedRequestObject.request;
      } else {
        const cache = instance(ctx.oidc.provider).requestUriCache;
        params.request = await cache.resolve(params.request_uri);
      }
      if (!params.request) throw new Error();
      params.request_uri = undefined;
    } catch (err) {
      throw new InvalidRequestUri('could not load or parse request_uri', err.message);
    }
  }

  return next();
}
