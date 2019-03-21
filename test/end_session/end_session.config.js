const config = require('../default.config');

module.exports = {
  config,
  clients: [
    {
      client_id: 'client',
      response_types: ['id_token'],
      grant_types: ['implicit'],
      redirect_uris: ['https://client.example.com/cb'],
      token_endpoint_auth_method: 'none',
    },
  ],
};
