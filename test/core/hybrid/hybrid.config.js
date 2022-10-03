const config = require('../../default.config');

module.exports = {
  config,
  clients: [{
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['implicit', 'authorization_code', 'refresh_token'],
    response_types: ['code id_token', 'code token', 'code id_token token', 'none'],
    redirect_uris: ['https://client.example.com/cb'],
  }, {
    client_id: 'client-no-refresh',
    client_secret: 'secret',
    grant_types: ['implicit', 'authorization_code'],
    response_types: ['code id_token', 'code token', 'code id_token token', 'none'],
    redirect_uris: ['https://client.example.com/cb'],
  }],
};
