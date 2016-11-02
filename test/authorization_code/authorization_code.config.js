'use strict';

const config = require('../default.config');

module.exports = {
  config,
  clients: [{
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
  }, {
    client_id: 'client2',
    client_secret: 'secret',
    redirect_uris: ['https://client.example.com/cb']
  }]
};
