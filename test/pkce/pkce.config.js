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
    client_id: 'client',
    client_secret: 'secret',
    response_types: ['code', 'code id_token', 'id_token'],
    grant_types: ['authorization_code', 'refresh_token', 'implicit'],
    redirect_uris: ['https://rp.example.com/cb'],
  }],
};
