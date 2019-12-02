const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const config = cloneDeep(require('../default.config'));

merge(config.features, { webMessageResponseMode: { enabled: true } });

module.exports = {
  config,
  client: {
    client_id: 'client',
    grant_types: ['implicit'],
    response_types: ['id_token token'],
    redirect_uris: ['https://client.example.com'],
    web_message_uris: ['https://auth.example.com'],
    token_endpoint_auth_method: 'none',
  },
};
