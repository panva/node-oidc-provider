'use strict';

const _ = require('lodash');
const config = _.clone(require('../default.config'));

config.features = { request: true, requestUri: true };

module.exports = {
  config,
  clients: [{
    client_id: 'client',
    client_secret: 'secret',
    redirect_uris: ['https://client.example.com/cb'],
  }, {
    client_id: 'client-with-HS-sig',
    client_secret: 'atleast32byteslongforHS256mmkay?',
    request_object_signing_alg: 'HS256',
    redirect_uris: ['https://client.example.com/cb'],
  }],
};
