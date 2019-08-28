const cloneDeep = require('lodash/cloneDeep');

const config = cloneDeep(require('../default.config'));

module.exports = {
  config,
  clients: [
    {
      client_id: 'client',
      response_types: ['id_token'],
      grant_types: ['implicit'],
      redirect_uris: ['https://client.example.com/cb'],
      token_endpoint_auth_method: 'none',
    },
    {
      client_id: 'client-hmac',
      client_secret: 'secret',
      response_types: ['id_token'],
      grant_types: ['implicit'],
      redirect_uris: ['https://client.example.com/cb'],
      token_endpoint_auth_method: 'none',
      id_token_signed_response_alg: 'HS256',
    },
  ],
};
