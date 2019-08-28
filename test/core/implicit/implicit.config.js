const config = require('../../default.config');

module.exports = {
  config,
  clients: [{
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['implicit', 'authorization_code'],
    response_types: ['id_token', 'id_token token', 'code token', 'none'],
    redirect_uris: ['https://client.example.com/cb'],
  }, {
    client_id: 'client-expired-secret',
    client_secret: 'secret',
    id_token_signed_response_alg: 'HS256',
    client_secret_expires_at: 1,
    grant_types: ['implicit', 'authorization_code'],
    response_types: ['id_token', 'id_token token', 'code token', 'none'],
    redirect_uris: ['https://client.example.com/cb'],
  }, {
    client_id: 'client-expired-secret-encrypted',
    client_secret: 'secret',
    id_token_signed_response_alg: 'RS256',
    id_token_encrypted_response_alg: 'dir',
    client_secret_expires_at: 1,
    grant_types: ['implicit', 'authorization_code'],
    response_types: ['id_token', 'id_token token', 'code token', 'none'],
    redirect_uris: ['https://client.example.com/cb'],
  }],
};
