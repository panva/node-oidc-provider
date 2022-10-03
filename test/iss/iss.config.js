const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const config = cloneDeep(require('../default.config'));

merge(config.features, {
  jwtResponseModes: { enabled: true },
});

module.exports = {
  config,
  clients: [{
    client_id: 'client',
    token_endpoint_auth_method: 'none',
    redirect_uris: ['https://client.example.com/cb'],
    grant_types: ['authorization_code', 'implicit'],
    scope: 'openid',
    response_types: [
      'code id_token token',
      'code id_token',
      'code token',
      'code',
      'id_token token',
      'id_token',
      'none',
    ],
  }],
};
