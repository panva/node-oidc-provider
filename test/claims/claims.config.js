'use strict';

const cert = require('../default.sig.key');
const config = require('../default.config');

config.features = { claimsParameter: true };

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['implicit'],
    response_types: ['id_token token', 'none', 'id_token'],
    redirect_uris: ['https://client.example.com/cb'],
  },
  certs: [cert],
};
