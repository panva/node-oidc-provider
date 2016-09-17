'use strict';

const config = require('../default.config');

module.exports = {
  config,
  client: {
    application_type: 'native',
    client_id: 'client',
    client_secret: 'secret',
    redirect_uris: ['myapp://localhost/cb'],
  }
};
