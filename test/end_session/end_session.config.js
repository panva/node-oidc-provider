import getConfig from '../default.config.js';

const config = getConfig();

export default {
  config,
  clients: [
    {
      client_id: 'client',
      response_types: ['id_token', 'code'],
      grant_types: ['implicit', 'authorization_code'],
      redirect_uris: ['https://client.example.com/cb'],
      token_endpoint_auth_method: 'none',
    },
    {
      client_id: 'client-hmac',
      client_secret: 'secret',
      response_types: ['id_token', 'code'],
      grant_types: ['implicit', 'authorization_code'],
      redirect_uris: ['https://client.example.com/cb'],
      token_endpoint_auth_method: 'none',
      id_token_signed_response_alg: 'HS256',
    },
  ],
};
