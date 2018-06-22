const { clone } = require('lodash');

const config = clone(require('../default.config'));

config.features = { sessionManagement: true };

config.prompts = ['consent', 'login', 'none', 'custom'];

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    redirect_uris: ['https://client.example.com/cb'],
  },
};
