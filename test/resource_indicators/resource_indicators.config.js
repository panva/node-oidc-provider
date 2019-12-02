const { strict: assert } = require('assert');
const { URL } = require('url');

const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const config = cloneDeep(require('../default.config'));
const { errors: { InvalidTarget } } = require('../../lib');

config.whitelistedJWA.requestObjectSigningAlgValues = ['none'];
merge(config.features, {
  requestObjects: { request: true },
  clientCredentials: { enabled: true },
  deviceFlow: { enabled: true },
  resourceIndicators: {
    enabled: true,
    allowedPolicy(ctx, resources, client) {
      assert(Array.isArray(resources));
      assert(client instanceof ctx.oidc.provider.Client);
      if (resources.includes('urn:example:bad')) {
        return false;
      }

      return true;
    },
  },
});

config.audiences = ({ oidc: { params, route, entities } }, sub, token, use) => {
  if (['access_token', 'client_credentials'].includes(use)) {
    const resourceParam = params.resource;
    let resources = [];
    if (Array.isArray(resourceParam)) {
      resources = resources.concat(resourceParam);
    } else if (resourceParam) {
      resources.push(resourceParam);
    }

    if (route === 'token') {
      const { grant_type } = params;
      let grantedResource;
      switch (grant_type) {
        case 'authorization_code':
          grantedResource = entities.AuthorizationCode.resource;
          break;
        case 'refresh_token':
          grantedResource = entities.RefreshToken.resource;
          break;
        case 'urn:ietf:params:oauth:grant-type:device_code':
          grantedResource = entities.DeviceCode.resource;
          break;
        default:
      }
      if (Array.isArray(grantedResource)) {
        resources = resources.concat(grantedResource);
      } else if (grantedResource) {
        resources.push(grantedResource);
      }
    }

    resources.forEach((aud) => {
      const { protocol } = new URL(aud);
      if (!['https:', 'urn:'].includes(protocol)) {
        throw new InvalidTarget('resources must be https URIs or URNs');
      }
    });

    return resources.length === 1 ? resources[0] : resources;
  }

  return undefined;
};

module.exports = {
  config,
  client: {
    client_id: 'client',
    token_endpoint_auth_method: 'none',
    redirect_uris: ['https://client.example.com/cb'],
    grant_types: [
      'implicit',
      'authorization_code',
      'refresh_token',
      'urn:ietf:params:oauth:grant-type:device_code',
      'client_credentials',
    ],
    response_types: ['id_token token', 'code'],
  },
};
