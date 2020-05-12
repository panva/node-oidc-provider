const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const config = cloneDeep(require('../default.config'));

merge(config.features, {
  introspection: { enabled: true },
  revocation: { enabled: true },
});
config.pkce = { methods: ['plain', 'S256'] };

module.exports = {
  config,
  clients: [{
    client_id: 'clientPost',
    token_endpoint_auth_method: 'client_secret_post',
    client_secret: 'secret',
    grant_types: ['authorization_code', 'implicit', 'refresh_token'],
    response_types: ['code', 'id_token', 'code id_token'],
    redirect_uris: ['https://rp.example.com/cb'],
  }, {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code', 'refresh_token'],
    redirect_uris: ['https://rp.example.com/cb'],
  }, {
    token_endpoint_auth_method: 'none',
    client_id: 'clientNone',
    grant_types: ['authorization_code', 'refresh_token'],
    redirect_uris: ['https://rp.example.com/cb'],
  }, {
    response_types: ['code', 'code id_token', 'id_token'],
    application_type: 'native',
    token_endpoint_auth_method: 'none',
    client_id: 'native',
    grant_types: ['authorization_code', 'refresh_token', 'implicit'],
    redirect_uris: ['https://rp.example.com/cb'],
  }],
};
