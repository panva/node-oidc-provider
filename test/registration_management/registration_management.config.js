const { clone } = require('lodash');

const config = clone(require('../default.config'));

config.features = {
  registrationManagement: { enabled: true },
  registration: { enabled: true },
};

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    redirect_uris: ['https://client.example.com/cb'],
  },
};
