const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const errors = require('../../lib/helpers/errors');
const config = cloneDeep(require('../default.config'));

merge(config.features, {
  clientCredentials: { enabled: true },
  resourceIndicators: {
    getResourceServerInfo(ctx, resourceIndicator) {
      const [, wl, format] = resourceIndicator.split(':');
      if (wl.includes('wl')) {
        return {
          scope: 'api:read api:write',
          accessTokenFormat: format || 'opaque',
        };
      }

      throw new errors.InvalidTarget();
    },
    defaultResource(ctx) {
      if (ctx.oidc.body && ctx.oidc.body.nodefault) {
        return undefined;
      }

      return 'urn:wl:opaque:default';
    },
  },
});

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['client_credentials'],
    response_types: [],
    redirect_uris: [],
  },
};
