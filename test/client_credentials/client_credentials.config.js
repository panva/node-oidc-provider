'use strict';

const _ = require('lodash');
const cert = require('../default.sig.key');
const config = _.clone(require('../default.config'));

config.features = { clientCredentials: true };

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code', 'client_credentials'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
  },
  certs: [cert],
};
