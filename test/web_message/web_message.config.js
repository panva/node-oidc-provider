import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, { webMessageResponseMode: { enabled: true } });

export default {
  config,
  client: {
    client_id: 'client',
    grant_types: ['implicit', 'authorization_code'],
    response_types: ['code id_token token', 'code'],
    redirect_uris: ['https://client.example.com'],
    web_message_uris: ['https://auth.example.com'],
    token_endpoint_auth_method: 'none',
  },
};
