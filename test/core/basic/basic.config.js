'use strict';

const config = require('../../default.config');

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code'],
    response_types: ['code', 'none'],
    redirect_uris: ['https://client.example.com/cb'],
  }
};
