/* eslint-disable no-underscore-dangle */
import instance from '../helpers/weak_cache.js';
import { InvalidTarget } from '../helpers/errors.js';

const filterStatics = (ctx) => {
  if (ctx.oidc.params.scope && !ctx.oidc.params.resource) {
    ctx.oidc.params.scope = [...ctx.oidc.requestParamOIDCScopes].join(' ');
  }
};

function emptyResource(params) {
  return !params.resource || (Array.isArray(params.resource) && !params.resource.length);
}

export default async function checkResource(ctx, next) {
  const {
    oidc: {
      params,
      provider,
      client,
      resourceServers,
    },
  } = ctx;

  const {
    defaultResource,
    enabled,
    getResourceServerInfo,
  } = instance(provider).features.resourceIndicators;

  if (!enabled) {
    filterStatics(ctx);
    return next();
  }

  if (params.resource === undefined) {
    params.resource = await defaultResource(ctx, client);

    if (params.authorization_details && emptyResource(params)) {
      throw new InvalidTarget('resource indicator must be provided or defaulted to when Rich Authorization Requests are used');
    }
  }

  if (params.scope && emptyResource(params)) {
    filterStatics(ctx);
    return next();
  }

  let { resource } = params;

  if (params.resource === undefined) {
    return next();
  }

  if (!Array.isArray(params.resource)) {
    resource = [resource];
  }

  for (const identifier of resource) {
    const href = URL.parse(identifier)?.href;

    if (!href) {
      throw new InvalidTarget('resource indicator must be an absolute URI');
    }

    // NOTE: we don't check for new URL() => search of hash because of an edge case
    // new URL('https://example.com?#') => search and hash are empty, seems like an inconsistent validation
    if (href.includes('#')) {
      throw new InvalidTarget('resource indicator must not contain a fragment component');
    }

    const resourceServer = await getResourceServerInfo(ctx, identifier, client);
    resourceServers[identifier] = new ctx.oidc.provider.ResourceServer(identifier, resourceServer);
  }

  return next();
}
