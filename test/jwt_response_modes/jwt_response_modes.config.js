const { clone } = require('lodash');

const config = clone(require('../default.config'));

config.features = {
  encryption: { enabled: true },
  webMessageResponseMode: { enabled: true },
  jwtResponseModes: { enabled: true },
};

module.exports = {
  config,
  clients: [
    {
      client_id: 'client',
      grant_types: ['authorization_code', 'implicit'],
      response_types: ['code', 'id_token token', 'none'],
      redirect_uris: ['https://client.example.com'],
      token_endpoint_auth_method: 'none',
    },
    {
      client_id: 'client-encrypted',
      client_secret: 'secret',
      grant_types: ['authorization_code', 'implicit'],
      response_types: ['code', 'id_token token', 'none'],
      redirect_uris: ['https://client.example.com'],
      authorization_encrypted_response_alg: 'A128KW',
    },
  ],
};
