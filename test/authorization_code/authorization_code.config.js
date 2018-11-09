const config = require('../default.config');

module.exports = {
  config,
  clients: [{
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb', 'https://client.example.com/cb2'],
  }, {
    client_id: 'client2',
    client_secret: 'secret',
    grant_types: ['authorization_code', 'refresh_token'],
    redirect_uris: ['https://client.example.com/cb3'],
  }],
};
