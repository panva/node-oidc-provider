const { clone } = require('lodash');
const config = clone(require('../default.config'));

config.features = { claimsParameter: true };
config.acrValues = ['0', '1', '2'];

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['implicit'],
    response_types: ['id_token token', 'none', 'id_token'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
