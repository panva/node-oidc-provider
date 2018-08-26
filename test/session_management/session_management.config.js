const { clone } = require('lodash');

const config = clone(require('../default.config'));

config.features = { sessionManagement: true };
config.interactionCheck = () => {};

module.exports = {
  config,
  clients: [
    {
      client_id: 'client',
      client_secret: 'secret',
      response_types: ['code', 'id_token'],
      grant_types: ['authorization_code', 'implicit'],
      redirect_uris: ['https://client.example.com/cb'],
    },
    {
      client_id: 'client-native-claimed',
      client_secret: 'secret',
      application_type: 'native',
      redirect_uris: ['https://client.example.com/cb'],
    },
  ],
};
