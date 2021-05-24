const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const config = cloneDeep(require('../default.config'));
const errors = require('../../lib/helpers/errors');

merge(config, {
  issueRefreshToken() {
    return true;
  },
  features: {
    introspection: { enabled: true },
    clientCredentials: { enabled: true },
    deviceFlow: { enabled: true },
    resourceIndicators: {
      enabled: true,
      useGrantedResource(ctx) {
        return ctx.oidc.body && ctx.oidc.body.usegranted;
      },
      getResourceServerInfo(ctx, resource) {
        if (resource.includes('wl')) {
          return {
            audience: resource,
            scope: 'api:read api:write',
          };
        }

        throw new errors.InvalidTarget();
      },
      defaultResource(ctx) {
        if (ctx.oidc.body && ctx.oidc.body.nodefault) {
          return undefined;
        }

        return 'urn:wl:default';
      },
    },
  },
});

module.exports = {
  config,
  clients: [
    {
      client_id: 'client',
      token_endpoint_auth_method: 'none',
      redirect_uris: ['https://client.example.com/cb'],
      response_types: [
        'id_token',
        'id_token token',
        'code',
      ],
      grant_types: [
        'implicit',
        'refresh_token',
        'client_credentials',
        'authorization_code',
        'urn:ietf:params:oauth:grant-type:device_code',
      ],
    },
  ],
};
