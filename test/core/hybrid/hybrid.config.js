const config = require('../../default.config');

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['implicit', 'authorization_code'],
    response_types: ['code id_token', 'code token', 'code id_token token', 'none'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
