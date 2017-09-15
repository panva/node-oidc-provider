const config = require('../default.config');

module.exports = {
  config,
  clients: [{
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['implicit', 'authorization_code'],
    response_types: ['code id_token', 'code token', 'code id_token token', 'none', 'id_token'],
    redirect_uris: ['https://client.example.com/cb'],
  }, {
    client_id: 'client-sig-none',
    client_secret: 'secret',
    response_types: ['code'],
    grant_types: ['authorization_code'],
    id_token_signed_response_alg: 'none',
    redirect_uris: ['https://client.example.com/cb'],
  }, {
    client_id: 'client-sig-HS256',
    client_secret: 'atleast32byteslongforHS256mmkay?',
    response_types: ['code'],
    grant_types: ['authorization_code'],
    id_token_signed_response_alg: 'HS256',
    redirect_uris: ['https://client.example.com/cb'],
  }],
};
