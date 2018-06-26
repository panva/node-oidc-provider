const config = require('../default.config');

module.exports = {
  config,
  clients: [{
    client_id: 'client',
    client_secret: 'secret',
    redirect_uris: ['https://client.example.com/cb'],
  }],
};
