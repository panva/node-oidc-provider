'use strict';

const _ = require('lodash');
const config = _.clone(require('../default.config'));

config.features = { refreshToken: true };

module.exports = {
  config,
  clients: [{
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
  }, {
    client_id: 'client2',
    client_secret: 'secret',
    grant_types: ['authorization_code', 'refresh_token'],
    redirect_uris: ['https://client.example.com/cb']
  }]
};
