'use strict';

const cert = require('../default.sig.key');
const config = require('../default.config');

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    subject_type: 'pairwise',
    redirect_uris: ['https://client.example.com/cb'],
  },
  certs: [cert],
};
