const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const config = cloneDeep(require('../default.config'));

config.subjectTypes = ['public', 'pairwise'];
merge(config.features, {
  introspection: { enabled: true },
  encryption: { enabled: true },
  clientCredentials: { enabled: true },
});

module.exports = {
  config,
  clients: [{
    client_id: 'client',
    client_secret: 'secret',
    redirect_uris: ['https://client.example.com/cb'],
  }, {
    client_id: 'client-pairwise',
    client_secret: 'secret',
    subject_type: 'pairwise',
    redirect_uris: ['https://client.example.com/cb'],
  }, {
    client_id: 'client-introspection',
    client_secret: 'secret',
    redirect_uris: [],
    response_types: [],
    grant_types: [],
  }, {
    client_id: 'client-none',
    token_endpoint_auth_method: 'none',
    redirect_uris: [],
    grant_types: [],
    response_types: [],
  }],
};
