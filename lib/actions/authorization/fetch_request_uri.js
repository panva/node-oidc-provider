const { URL } = require('url');
const { strict: assert } = require('assert');

const { InvalidRequestUri } = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');
const { PUSHED_REQUEST_URN } = require('../../consts');

const allowedSchemes = new Set(['http:', 'https:', 'urn:']);

const loadPushedAuthorizationRequest = require('./load_pushed_authorization_request');
const rejectRequestAndUri = require('./reject_request_and_uri');

/*
 * Validates request_uri length, protocol and its presence in client allow list and either uses
 * previously cached response or loads a fresh state. Removes request_uri form the parameters and
 * uses the response body as a value for the request parameter to be validated by a downstream
 * middleware
 *
 *
 * @throws: invalid_request
 * @throws: invalid_request_uri
 * @throws: request_not_supported
 * @throws: request_uri_not_supported
 */
module.exports = async function fetchRequestUri(ctx, next) {
  const { pushedAuthorizationRequests, requestObjects } = instance(ctx.oidc.provider).configuration('features');
  const { params } = ctx.oidc;

  rejectRequestAndUri(ctx, () => {});

  if (params.request_uri !== undefined) {
    let protocol;
    try {
      ({ protocol } = new URL(params.request_uri));
      assert(allowedSchemes.has(protocol));
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
      throw new InvalidRequestUri('only request_uri values from the pushed_authorization_request_endpoint are allowed');
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
      assert(params.request);
      params.request_uri = undefined;
    } catch (err) {
      throw new InvalidRequestUri('could not load or parse request_uri', err.message);
    }
  }

  return next();
};
