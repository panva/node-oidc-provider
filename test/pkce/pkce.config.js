import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, {
  introspection: { enabled: true },
  revocation: { enabled: true },
});

export default {
  config,
  clients: [{
    client_id: 'client',
    response_types: ['code', 'code id_token', 'id_token'],
    grant_types: ['authorization_code', 'refresh_token', 'implicit'],
    redirect_uris: ['https://rp.example.com/cb'],
    token_endpoint_auth_method: 'none',
  }],
};
