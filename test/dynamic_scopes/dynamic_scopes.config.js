const { clone } = require('lodash');

const config = clone(require('../default.config'));

config.features = {
  deviceCode: true,
  clientCredentials: true,
};

const SIGN = /^sign:[a-fA-F0-9]{2,}$/;
config.dynamicScopes = [SIGN];
config.claims = new Map(Object.entries(config.claims));
config.claims.set(SIGN, ['updated_at']);

module.exports = {
  config,
  client: {
    client_id: 'client',
    grant_types: [
      'authorization_code',
      'client_credentials',
      'implicit',
    ],
    response_types: ['code token'],
    redirect_uris: ['https://client.example.com/cb'],
    token_endpoint_auth_method: 'none',
  },
};
