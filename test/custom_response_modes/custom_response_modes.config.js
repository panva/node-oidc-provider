const cloneDeep = require('lodash/cloneDeep');

const config = cloneDeep(require('../default.config'));

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
  },
};
