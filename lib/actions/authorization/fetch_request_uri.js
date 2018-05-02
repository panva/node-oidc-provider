const RequestUriCache = require('../../helpers/request_uri_cache');
const { InvalidRequestUri } = require('../../helpers/errors');

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
    const { params } = ctx.oidc;

    if (params.request_uri !== undefined) {
      if (params.request_uri.length > 512) {
        ctx.throw(new InvalidRequestUri('the request_uri MUST NOT exceed 512 characters'));
      }

      if (!params.request_uri.startsWith('https://')) {
        ctx.throw(new InvalidRequestUri('request_uri must use https scheme'));
      }

      if (ctx.oidc.client.requestUris) {
        if (!ctx.oidc.client.requestUriAllowed(params.request_uri)) {
          ctx.throw(new InvalidRequestUri('not registered request_uri provided'));
        }
      }

      try {
        params.request = await cache.resolve(params.request_uri);
        params.request_uri = undefined;
      } catch (err) {
        ctx.throw(new InvalidRequestUri(`could not load or parse request_uri (${err.message})`));
      }
    }

    await next();
  };
};
