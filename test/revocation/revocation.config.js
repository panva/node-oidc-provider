const clone = require('lodash/clone');

const config = clone(require('../default.config'));

config.features = { revocation: { enabled: true }, clientCredentials: { enabled: true } };

module.exports = {
  config,
  clients: [
    {
      client_id: 'client',
      client_secret: 'secret',
      redirect_uris: ['https://client.example.com/cb'],
    },
    {
      client_id: 'client2',
      client_secret: 'secret',
      redirect_uris: ['https://client2.example.com/cb'],
    },
  ],
};
