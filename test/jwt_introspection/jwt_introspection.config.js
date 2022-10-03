const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const config = cloneDeep(require('../default.config'));

merge(config.features, {
  introspection: { enabled: true },
  jwtIntrospection: { enabled: true },
  encryption: { enabled: true },
});

module.exports = {
  config,
  clients: [{
    client_id: 'client-signed',
    client_secret: 'secret',
    introspection_signed_response_alg: 'RS256',
    redirect_uris: ['https://client.example.com/cb'],
  },
  {
    client_id: 'client-HS-expired',
    client_secret: 'secret',
    client_secret_expires_at: 1,
    introspection_endpoint_auth_method: 'none',
    introspection_signed_response_alg: 'HS256',
    redirect_uris: ['https://client.example.com/cb'],
  },
  {
    client_id: 'client-encrypted',
    client_secret: 'secret',
    introspection_endpoint_auth_method: 'none',
    introspection_encrypted_response_alg: 'PBES2-HS256+A128KW',
    redirect_uris: ['https://client.example.com/cb'],
  }],
};
