const config = require('../default.config');

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['implicit'],
    response_types: ['id_token token', 'id_token'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
