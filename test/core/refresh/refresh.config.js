'use strict';
const cert = require('../../default.sig.key');
const config = require('../../default.config');

config.features = { refreshToken: true };

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
  },
  certs: [cert],
};
