import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, {
  clientCredentials: { enabled: true },
  deviceFlow: { enabled: true },
});

export default {
  config,
  client: {
    client_id: 'client',
    token_endpoint_auth_method: 'none',
    grant_types: [
      'client_credentials',
      'authorization_code',
      'implicit',
      'refresh_token',
      'urn:ietf:params:oauth:grant-type:device_code',
    ],
    response_types: ['code', 'code id_token token'],
    redirect_uris: ['https://rp.example.com/cb'],
  },
};
