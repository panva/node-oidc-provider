import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, {
  jwtResponseModes: { enabled: true },
});

export default {
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
