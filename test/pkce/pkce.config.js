'use strict';

const config = require('../default.config');

module.exports = {
  config,
  clients: [{
    application_type: 'native',
    client_id: 'clientPost',
    token_endpoint_auth_method: 'client_secret_post',
    client_secret: 'secret',
    redirect_uris: ['myapp://localhost/cb'],
  }, {
    application_type: 'native',
    client_id: 'client',
    client_secret: 'secret',
    redirect_uris: ['myapp://localhost/cb'],
  }],
};
