const { URL } = require('url');

const { cloneDeep } = require('lodash');

const config = cloneDeep(require('../default.config'));
const { errors: { InvalidTarget } } = require('../../lib');

config.whitelistedJWA.requestObjectSigningAlgValues = ['none'];
config.features = {
  request: true,
  clientCredentials: true,
  deviceFlow: true,
  alwaysIssueRefresh: true,
  resourceIndicators: true,
};

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

    return resources;
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
