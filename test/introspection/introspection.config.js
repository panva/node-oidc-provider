const { clone } = require('lodash');
const config = clone(require('../default.config'));

config.subjectTypes = ['public', 'pairwise'];
config.pairwiseSalt = 'foobar';
config.features = { introspection: true };

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
    redirect_uris: ['https://client.example.com/cb']
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
    response_types: []
  }]
};
