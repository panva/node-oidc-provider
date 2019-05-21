const { clone } = require('lodash');

const config = clone(require('../default.config'));

config.audiences = () => ['foo', 'bar'];

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    grant_types: ['implicit', 'authorization_code', 'refresh_token'],
    response_types: ['code id_token token'],
    redirect_uris: ['https://client.example.com/cb'],
    userinfo_signed_response_alg: 'RS256',
  },
};
