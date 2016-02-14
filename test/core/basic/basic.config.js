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
    responseTypesSupported: ['code', 'none'],
    scopes: ['openid'],
    subjectTypesSupported: ['public'],
    tokenEndpointAuthMethodsSupported: ['client_secret_basic', 'client_secret_post']
  },
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
  },
  certs: [
    require('../../default.sig.key')
  ]
};
