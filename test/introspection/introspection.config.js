import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

config.subjectTypes = ['public', 'pairwise'];
merge(config.features, {
  introspection: { enabled: true },
  encryption: { enabled: true },
  clientCredentials: { enabled: true },
});

export default {
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
