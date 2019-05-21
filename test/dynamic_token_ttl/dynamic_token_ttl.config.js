const { cloneDeep } = require('lodash');

const config = cloneDeep(require('../default.config'));

config.features = {
  clientCredentials: { enabled: true },
  deviceFlow: { enabled: true },
};

module.exports = {
  config,
  client: {
    client_id: 'client',
    token_endpoint_auth_method: 'none',
    grant_types: [
      'client_credentials',
      'authorization_code',
      'implicit',
      'refresh_token',
      'urn:ietf:params:oauth:grant-type:device_code',
    ],
    response_types: ['code', 'code id_token token'],
    redirect_uris: ['https://rp.example.com/cb'],
  },
};
