import cors from '@koa/cors';

import { InvalidRequest } from '../helpers/errors.js';
import instance from '../helpers/weak_cache.js';

function checkClientCORS(ctx, client) {
  const origin = ctx.get('Origin');
  const { clientBasedCORS } = instance(ctx.oidc.provider).configuration();

  const allowed = clientBasedCORS(ctx, origin, client);

  if (typeof allowed !== 'boolean') {
    throw new Error('clientBasedCORS helper must be a synchronous function returning a Boolean');
  }

  if (!allowed) {
    ctx.remove('Access-Control-Allow-Origin');
    throw new InvalidRequest(`origin ${origin} not allowed for client: ${client.clientId}`);
  }
}

export default ({ clientBased = false, ...options }) => {
  const builtin = cors({
    keepHeadersOnError: false,
    origin(ctx) {
      return ctx.get('Origin') || '*';
    },
    ...options,
  });

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

    await new Promise((resolve) => { builtin(ctx, resolve); });

    ctx.oidc.once('assign.client', checkClientCORS);

    return next();
  };
};
