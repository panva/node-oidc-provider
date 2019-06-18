const { URL } = require('url');
const assert = require('assert');

const {
  InvalidRequest, InvalidRequestUri, RequestNotSupported, RequestUriNotSupported,
} = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');

const allowedSchemes = new Set(['http:', 'https:', 'urn:']);

/*
 * Validates request_uri length, protocol and its presence in client whitelist and either uses
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
  const { request, requestUri } = instance(ctx.oidc.provider).configuration('features');
  const { client, params } = ctx.oidc;

  if (!request.enabled && params.request !== undefined) {
    throw new RequestNotSupported();
  }

  if (!requestUri.enabled && params.request_uri !== undefined) {
    throw new RequestUriNotSupported();
  }

  if (params.request !== undefined && params.request_uri !== undefined) {
    throw new InvalidRequest('request and request_uri parameters MUST NOT be used together');
  }

  if (
    client.requestObjectSigningAlg
    && params.request === undefined
    && params.request_uri === undefined
  ) {
    throw new InvalidRequest('request or request_uri must be provided for this client');
  }

  if (params.request_uri !== undefined) {
    let protocol;
    try {
      ({ protocol } = new URL(params.request_uri));
      assert(allowedSchemes.has(protocol));
    } catch (err) {
      throw new InvalidRequestUri('invalid request_uri scheme');
    }

    if (ctx.oidc.client.requestUris || protocol === 'urn:') {
      if (!ctx.oidc.client.requestUriAllowed(params.request_uri)) {
        throw new InvalidRequestUri('not registered request_uri provided');
      }
    }

    if (protocol === 'http:') {
      ctx.oidc.insecureRequestUri = true;
    }

    const cache = instance(ctx.oidc.provider).requestUriCache;

    try {
      if (protocol === 'urn:') {
        params.request = await cache.resolveUrn(params.request_uri);
      } else {
        params.request = await cache.resolveWebUri(params.request_uri);
      }
      assert(params.request);
      params.request_uri = undefined;
    } catch (err) {
      throw new InvalidRequestUri(`could not load or parse request_uri (${err.message})`);
    }
  }

  return next();
};
