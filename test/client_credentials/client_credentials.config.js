const { clone } = require('lodash');

const config = clone(require('../default.config'));

config.features = { clientCredentials: true };

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
