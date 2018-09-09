const { clone } = require('lodash');

const config = clone(require('../default.config'));

config.subjectTypes = ['pairwise', 'public'];
config.features = { claimsParameter: true };
config.acrValues = ['0', '1', '2'];
config.pairwiseIdentifier = sub => `${sub}-pairwise`;

module.exports = {
  config,
  clients: [
    {
      client_id: 'client',
      client_secret: 'secret',
      grant_types: ['implicit'],
      response_types: ['id_token token', 'none', 'id_token'],
      redirect_uris: ['https://client.example.com/cb'],
    },
    {
      client_id: 'client-pairwise',
      subject_type: 'pairwise',
      token_endpoint_auth_method: 'none',
      grant_types: ['implicit'],
      response_types: ['id_token'],
      redirect_uris: ['https://client.example.com/cb'],
    },
  ],
};
