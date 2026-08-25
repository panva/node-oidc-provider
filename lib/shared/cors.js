import { boolean } from '../helpers/configuration_result.js';
import { InvalidRequest } from '../helpers/errors.js';
import instance from '../helpers/weak_cache.js';

const list = (value) => (Array.isArray(value) ? value.join(',') : value);

/*
 * Transcribed from @koa/cors, limited to how it was called here: the origin is
 * always the request's Origin or '*', so it is never falsy; credentials,
 * allowHeaders, secureContext and privateNetworkAccess were never passed; and
 * keepHeadersOnError was pinned to false, which is what removes @koa/cors'
 * try/catch around next() - errors carry no CORS headers, as before.
 *
 * test/cors/cors_parity.test.js holds this to @koa/cors itself.
 */
function corsMiddleware({ allowMethods, maxAge, exposeHeaders }) {
  const methods = list(allowMethods) ?? 'GET,HEAD,PUT,POST,DELETE,PATCH';
  const expose = list(exposeHeaders);
  const age = maxAge ? String(maxAge) : undefined;

  return async (ctx, next) => {
    ctx.vary('Origin');

    const origin = ctx.get('Origin') || '*';

    if (ctx.method !== 'OPTIONS') {
      ctx.set('Access-Control-Allow-Origin', origin);
      if (expose) ctx.set('Access-Control-Expose-Headers', expose);
      return next();
    }

    // not a preflight, leave it alone
    if (!ctx.get('Access-Control-Request-Method')) return next();

    ctx.set('Access-Control-Allow-Origin', origin);
    if (age) ctx.set('Access-Control-Max-Age', age);
    if (methods) ctx.set('Access-Control-Allow-Methods', methods);

    const allowHeaders = ctx.get('Access-Control-Request-Headers');
    if (allowHeaders) ctx.set('Access-Control-Allow-Headers', allowHeaders);

    ctx.status = 204;
    return undefined;
  };
}

function checkClientCORS(ctx, client) {
  const origin = ctx.get('Origin');
  const { clientBasedCORS } = instance(ctx.oidc.provider).configuration;

  const allowed = boolean(clientBasedCORS(ctx, origin, client), 'clientBasedCORS');

  if (!allowed) {
    ctx.remove('Access-Control-Allow-Origin');
    throw new InvalidRequest(`origin ${origin} not allowed for client: ${client.clientId}`);
  }
}

export default ({ clientBased = false, ...options }) => {
  const builtin = corsMiddleware(options);

  return async (ctx, next) => {
    const headers = Object.keys(ctx.response.headers);

    // ignore built in CORS handling since the developer wants to do it their way
    if (headers.find((x) => x.toLowerCase().startsWith('access-control-'))) {
      return next();
    }

    ctx.vary('Origin');
    // preflights or generally available (e.g. discovery) -> CORS is allowed
    if (ctx.method === 'OPTIONS' || !clientBased || !ctx.get('Origin')) {
      return builtin(ctx, next);
    }

    ctx.oidc.once('assign.client', checkClientCORS);

    return builtin(ctx, next);
  };
};
