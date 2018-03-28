const { clone } = require('lodash');
const config = clone(require('../default.config'));

config.features = { pkce: { supportedMethods: ['plain', 'S256'] }, introspection: true, revocation: true };
config.interactionCheck = () => {};

module.exports = {
  config,
  clients: [{
    application_type: 'native',
    client_id: 'clientPost',
    token_endpoint_auth_method: 'client_secret_post',
    client_secret: 'secret',
    grant_types: ['authorization_code', 'implicit', 'refresh_token'],
    response_types: ['code', 'id_token', 'code id_token'],
    redirect_uris: ['com.example.myapp:/localhost/cb'],
  }, {
    application_type: 'native',
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code', 'refresh_token'],
    redirect_uris: ['com.example.myapp:/localhost/cb'],
  }, {
    application_type: 'native',
    token_endpoint_auth_method: 'none',
    client_id: 'clientNone',
    grant_types: ['authorization_code', 'refresh_token'],
    redirect_uris: ['com.example.myapp:/localhost/cb'],
  }],
};
