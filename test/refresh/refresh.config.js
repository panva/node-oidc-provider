const cloneDeep = require('lodash/cloneDeep');

const config = cloneDeep(require('../default.config'));

config.rotateRefreshToken = false;

module.exports = {
  config,
  clients: [{
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
  }, {
    client_id: 'client2',
    client_secret: 'secret',
    grant_types: ['authorization_code', 'refresh_token'],
    redirect_uris: ['https://client.example.com/cb'],
  }],
};
