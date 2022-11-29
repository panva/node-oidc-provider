import getConfig from '../default.config.js';

const config = getConfig();

export default {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['implicit'],
    response_types: ['id_token token', 'id_token'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
