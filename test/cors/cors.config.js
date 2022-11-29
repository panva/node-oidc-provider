import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, {
  introspection: { enabled: true },
  revocation: { enabled: true },
  deviceFlow: { enabled: true },
  clientCredentials: { enabled: true },
});

export default {
  config,
  client: {
    client_id: 'client',
    grant_types: ['client_credentials', 'urn:ietf:params:oauth:grant-type:device_code'],
    response_types: [],
    redirect_uris: [],
    token_endpoint_auth_method: 'none',
  },
};
