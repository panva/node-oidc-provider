'use strict';

module.exports = {
  config: {
    cookies: {
      long: {
        signed: false
      },
      short: {
        signed: false
      }
    },
    responseTypesSupported: ['id_token', 'id_token token', 'none', 'code', 'code token'],
    scopes: ['openid'],
    subjectTypesSupported: ['public'],
    tokenEndpointAuthMethodsSupported: ['client_secret_basic', 'client_secret_post']
  },
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
