'use strict';

const config = require('../default.config');
const clientKey = require('../client.sig.key');

module.exports = {
  config,
  clients: [{
    token_endpoint_auth_method: 'none',
    client_id: 'client-none',
    client_secret: 'secret',
    grant_types: ['implicit'],
    response_types: ['id_token'],
    redirect_uris: ['https://client.example.com/cb']
  }, {
    token_endpoint_auth_method: 'client_secret_basic',
    client_id: 'client-basic',
    client_secret: 'secret',
    redirect_uris: ['https://client.example.com/cb']
  }, {
    token_endpoint_auth_method: 'client_secret_post',
    client_id: 'client-post',
    client_secret: 'secret',
    redirect_uris: ['https://client.example.com/cb']
  }, {
    token_endpoint_auth_method: 'client_secret_jwt',
    client_id: 'client-jwt-secret',
    client_secret: 'atleast32byteslongforHS256mmkay?',
    redirect_uris: ['https://client.example.com/cb']
  }, {
    client_id: 'client-jwt-key',
    client_secret: 'whateverwontbeusedanyway',
    redirect_uris: ['https://client.example.com/cb'],
    token_endpoint_auth_method: 'private_key_jwt',
    jwks: {
      keys: [clientKey]
    }
  }]
};
