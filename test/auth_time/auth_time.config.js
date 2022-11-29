import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, { claimsParameter: { enabled: true } });

export default {
  config,
  clients: [{
    client_id: 'client',
    token_endpoint_auth_method: 'none',
    response_types: ['id_token'],
    grant_types: ['implicit'],
    redirect_uris: ['https://client.example.com/cb'],
  }, {
    client_id: 'client-with-require_auth_time',
    token_endpoint_auth_method: 'none',
    response_types: ['id_token'],
    grant_types: ['implicit'],
    redirect_uris: ['https://client.example.com/cb'],
    require_auth_time: true,
  }, {
    client_id: 'client-with-default_max_age',
    token_endpoint_auth_method: 'none',
    response_types: ['id_token'],
    grant_types: ['implicit'],
    redirect_uris: ['https://client.example.com/cb'],
    default_max_age: 999,
  }],
};
