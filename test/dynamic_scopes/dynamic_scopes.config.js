const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const config = cloneDeep(require('../default.config'));
const { DYNAMIC_SCOPE_LABEL } = require('../../lib/consts');

merge(config.features, {
  clientCredentials: { enabled: true },
});

const SIGN = /^sign:[a-fA-F0-9]{2,}$/;
SIGN[DYNAMIC_SCOPE_LABEL] = 'sign:{hex}';
const READ = /^read:[a-fA-F0-9]{2,}$/;

config.dynamicScopes = [SIGN, READ];
config.claims = new Map(Object.entries(config.claims));
config.claims.set(SIGN, ['updated_at']);

module.exports = {
  config,
  clients: [{
    client_id: 'client',
    grant_types: [
      'authorization_code',
      'client_credentials',
      'implicit',
    ],
    response_types: ['code token'],
    redirect_uris: ['https://client.example.com/cb'],
    token_endpoint_auth_method: 'none',
  }, {
    client_id: 'client-limited-scope',
    token_endpoint_auth_method: 'none',
    redirect_uris: ['https://client.example.com/cb'],
    scope: 'openid',
    grant_types: [
      'authorization_code',
      'client_credentials',
    ],
  }],
};
