const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const config = cloneDeep(require('../default.config'));

merge(config.features, {
  introspection: { enabled: true },
  revocation: { enabled: true },
  deviceFlow: { enabled: true },
  clientCredentials: { enabled: true },
});

module.exports = {
  config,
  client: {
    client_id: 'client',
    grant_types: ['client_credentials', 'urn:ietf:params:oauth:grant-type:device_code'],
    response_types: [],
    redirect_uris: [],
    token_endpoint_auth_method: 'none',
  },
};
