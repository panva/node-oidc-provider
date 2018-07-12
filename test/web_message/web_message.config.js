const { clone } = require('lodash');

const config = clone(require('../default.config'));

config.features = { webMessageResponseMode: true };

module.exports = {
  config,
  client: {
    client_id: 'client',
    grant_types: ['implicit'],
    response_types: ['id_token'],
    redirect_uris: ['https://client.example.com'],
    web_message_uris: ['https://auth.example.com'],
    token_endpoint_auth_method: 'none',
  },
};
