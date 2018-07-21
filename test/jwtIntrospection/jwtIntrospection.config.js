const { clone } = require('lodash');

const config = clone(require('../default.config'));

config.features = {
  introspection: true, jwtIntrospection: true, encryption: true,
};

module.exports = {
  config,
  clients: [{
    client_id: 'client-signed',
    client_secret: 'secret',
    introspection_signed_response_alg: 'RS256',
    redirect_uris: ['https://client.example.com/cb'],
  },
  {
    client_id: 'client-encrypted-none',
    client_secret: 'secret',
    introspection_endpoint_auth_method: 'none',
    introspection_encrypted_response_alg: 'PBES2-HS256+A128KW',
    redirect_uris: ['https://client.example.com/cb'],
  }],
};
