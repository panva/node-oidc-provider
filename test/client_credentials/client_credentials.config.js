const clone = require('lodash/clone');

const config = clone(require('../default.config'));

config.features = { clientCredentials: { enabled: true } };
config.scopes = ['api:read'];

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code', 'client_credentials'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
