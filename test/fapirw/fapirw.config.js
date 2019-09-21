const clone = require('lodash/clone');

const config = clone(require('../default.config'));

config.features = {
  fapiRW: { enabled: true },
  jwtResponseModes: { enabled: true },
  requestObjects: {
    request: true,
    mergingStrategy: { name: 'strict' },
  },
};
config.whitelistedJWA = {
  requestObjectSigningAlgValues: ['none'],
};

module.exports = {
  config,
  clients: [{
    client_id: 'client',
    response_types: ['code id_token', 'code'],
    grant_types: ['implicit', 'authorization_code'],
    redirect_uris: ['https://client.example.com/cb'],
    token_endpoint_auth_method: 'none',
  }],
};
