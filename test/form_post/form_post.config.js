const config = require('../default.config');

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code', 'implicit'],
    response_types: ['code', 'code id_token token'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
