'use strict';

const _ = require('lodash');
const config = _.clone(require('../default.config'));

config.features = { sessionManagement: true };

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    response_types: ['code', 'id_token'],
    grant_types: ['authorization_code', 'implicit'],
    redirect_uris: ['https://client.example.com/cb']
  }
};
