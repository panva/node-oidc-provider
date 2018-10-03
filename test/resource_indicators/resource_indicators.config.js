const { URL } = require('url');

const { cloneDeep } = require('lodash');

const config = cloneDeep(require('../default.config'));
const { errors: { InvalidResource } } = require('../../lib');

config.whitelistedJWA.requestObjectSigningAlgValues = ['none'];
config.features = {
  request: true,
  clientCredentials: true,
  deviceFlow: true,
  alwaysIssueRefresh: true,
  resourceIndicators: true,
};

config.audiences = ({ oidc: { params } }, sub, token, use) => {
  const { resource } = params;
  if (resource && ['access_token', 'client_credentials'].includes(use)) {
    let audiences = resource;
    if (!Array.isArray(resource)) {
      audiences = [resource];
    }
    audiences.forEach((aud) => {
      const { protocol } = new URL(aud);
      if (protocol !== 'https:') {
        throw new InvalidResource('resources must be https URIs');
      }
    });

    return audiences;
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
    response_types: ['code token'],
  },
};
