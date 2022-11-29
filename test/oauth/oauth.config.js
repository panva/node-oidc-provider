import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

delete config.claims;
config.responseTypes = [
  'code id_token token',
  'code id_token',
  'code token',
  'code',
  'id_token token',
  'id_token',
  'none',
];
config.scopes = ['openid', 'offline_access', 'api:read'];
merge(config.features, {
  claimsParameter: { enabled: true },
  deviceFlow: { enabled: true },
});

export default {
  config,
  client: {
    client_id: 'client',
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code', 'implicit', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code'],
    response_types: [
      'code id_token token',
      'code id_token',
      'code token',
      'code',
      'id_token token',
      'id_token',
      'none',
    ],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
