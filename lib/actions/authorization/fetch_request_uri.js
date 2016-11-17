'use strict';

const RequestUriCache = require('../../helpers/request_uri_cache');

/*
 * Validates request_uri length, protocol and it's presence in client whitelist and either uses
 * previously cached response or loads a fresh state. Removes request_uri form the parameters and
 * uses the response body as a value for the request parameter to be validated by a downstream
 * middleware
 *
 * @throws: invalid_request_uri
 * @see: RequestUriCache
 * @see: decodeRequest
 */
module.exports = (provider) => {
  const cache = new RequestUriCache(provider);

  return async function fetchRequestUri(ctx, next) {
    const params = ctx.oidc.params;

    if (params.request_uri !== undefined) {
      ctx.assert(params.request_uri.length <= 512, 400, 'invalid_request_uri', {
        error_description: 'the request_uri MUST NOT exceed 512 characters' });

      ctx.assert(params.request_uri.startsWith('https://'), 400,
        'invalid_request_uri', { error_description: 'request_uri must use https scheme' });

      if (ctx.oidc.client.requestUris) {
        ctx.assert(ctx.oidc.client.requestUriAllowed(params.request_uri), 400,
          'invalid_request_uri', { error_description: 'not registered request_uri provided' });
      }

      try {
        params.request = await cache.resolve(params.request_uri);
        params.request_uri = undefined;
      } catch (err) {
        ctx.throw(400, 'invalid_request_uri', {
          error_description: `could not load or parse request_uri (${err.message})` });
      }
    }

    await next();
  };
};
