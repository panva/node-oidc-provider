const { URL } = require('url');
const assert = require('assert');

const { InvalidRequestUri } = require('../../helpers/errors');
const instance = require('../../helpers/weak_cache');

const allowedSchemes = new Set(['http:', 'https:', 'urn:']);

/*
 * Validates request_uri length, protocol and its presence in client whitelist and either uses
 * previously cached response or loads a fresh state. Removes request_uri form the parameters and
 * uses the response body as a value for the request parameter to be validated by a downstream
 * middleware
 *
 * @throws: invalid_request_uri
 * @see: RequestUriCache
 * @see: decodeRequest
 */
module.exports = async function fetchRequestUri(ctx, next) {
  const { params } = ctx.oidc;

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
