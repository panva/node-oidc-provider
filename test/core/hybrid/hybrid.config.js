'use strict';

module.exports = {
  config: require('../../default.config'),
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['implicit', 'authorization_code'],
    response_types: ['code id_token', 'code token', 'code id_token token'],
    redirect_uris: ['https://client.example.com/cb'],
  },
  certs: [
    require('../../default.sig.key')
  ]
};
