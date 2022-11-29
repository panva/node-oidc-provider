import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, {
  claimsParameter: { enabled: true },
  jwtUserinfo: { enabled: true },
});

export default {
  config,
  clients: [{
    client_id: 'client',
    client_secret: 'secret',
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code', 'implicit', 'refresh_token'],
    response_types: [
      'code id_token token', 'code id_token', 'code token', 'code', 'id_token token', 'id_token',
    ],
    redirect_uris: ['https://client.example.com/cb'],
    userinfo_signed_response_alg: 'HS256',
  }],
};
