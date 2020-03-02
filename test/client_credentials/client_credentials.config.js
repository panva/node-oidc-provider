const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const config = cloneDeep(require('../default.config'));

merge(config.features, { clientCredentials: { enabled: true } });
config.scopes = ['api:read', 'api:write'];

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code', 'client_credentials'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
    scope: 'api:read',
  },
};
