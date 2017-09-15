const config = require('../../default.config');

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['implicit', 'authorization_code'],
    response_types: ['id_token', 'id_token token', 'code token', 'none'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
