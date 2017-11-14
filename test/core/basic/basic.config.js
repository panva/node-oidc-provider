const { clone } = require('lodash');
const config = clone(require('../../default.config'));

config.features = { requestUri: false };

module.exports = {
  config,
  clients: [{
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['authorization_code'],
    response_types: ['code', 'none'],
    redirect_uris: ['https://client.example.com/cb'],
  }, {
    application_type: 'native',
    client_id: 'client-native',
    client_secret: 'secret',
    grant_types: ['authorization_code'],
    response_types: ['code', 'none'],
    redirect_uris: ['com.example.app:/cb'],
  }],
};
