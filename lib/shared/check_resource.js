/* eslint-disable no-underscore-dangle */
/* eslint-disable no-await-in-loop */
const { URL } = require('url');

const instance = require('../helpers/weak_cache');
const { InvalidTarget } = require('../helpers/errors');

const filterStatics = (ctx) => {
  if (ctx.oidc.params.scope && !ctx.oidc.params.resource) {
    // eslint-disable-next-line no-restricted-syntax
    ctx.oidc.params.scope = [...ctx.oidc.requestParamOIDCScopes].join(' ');
  }
};

module.exports = async function checkResource(ctx, next) {
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
  } = instance(provider).configuration('features.resourceIndicators');

  if (!enabled) {
    filterStatics(ctx);
    return next();
  }

  if (params.resource === undefined) {
    params.resource = await defaultResource(ctx, client);
  }

  if (
    params.scope
    && (!params.resource || (Array.isArray(params.resource) && !params.resource.length))
  ) {
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

  // eslint-disable-next-line no-restricted-syntax
  for (const identifier of resource) {
    let href;
    try {
      ({ href } = new URL(resource));
    } catch (err) {
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
};
