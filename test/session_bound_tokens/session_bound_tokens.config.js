const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const config = cloneDeep(require('../default.config'));

merge(config.features, { deviceFlow: { enabled: true } });
config.issueRefreshToken = (ctx, client) => client.grantTypeAllowed('refresh_token');

module.exports = {
  config,
  clients: [
    {
      client_id: 'client',
      response_types: ['code', 'id_token token'],
      grant_types: ['authorization_code', 'implicit'],
      redirect_uris: ['https://client.example.com/cb'],
      token_endpoint_auth_method: 'none',
      scope: 'openid',
    },
    {
      client_id: 'client-refresh',
      response_types: ['code'],
      grant_types: ['authorization_code', 'refresh_token'],
      redirect_uris: ['https://client.example.com/cb'],
      token_endpoint_auth_method: 'none',
      scope: 'openid',
    },
    {
      client_id: 'client-offline',
      response_types: ['code'],
      grant_types: ['authorization_code', 'refresh_token'],
      redirect_uris: ['https://client.example.com/cb'],
      token_endpoint_auth_method: 'none',
      scope: 'openid offline_access',
    },
  ],
};
