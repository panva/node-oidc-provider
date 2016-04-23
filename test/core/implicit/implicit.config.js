'use strict';

module.exports = {
  config: require('../../default.config'),
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['implicit', 'authorization_code'],
    response_types: ['id_token', 'id_token token', 'code token'],
    redirect_uris: ['https://client.example.com/cb'],
  },
  certs: [
    require('../../default.sig.key')
  ]
};
