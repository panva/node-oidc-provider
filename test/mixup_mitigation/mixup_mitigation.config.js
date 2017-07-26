const { clone } = require('lodash');
const config = clone(require('../default.config'));

config.features = { mixupMitigation: true };
config.interactionCheck = () => {};

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    redirect_uris: ['https://client.example.com/cb'],
    response_types: ['code', 'id_token', 'code id_token', 'code token'],
    grant_types: ['authorization_code', 'implicit'],
  }
};
