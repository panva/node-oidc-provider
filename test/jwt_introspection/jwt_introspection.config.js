import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, {
  introspection: { enabled: true },
  jwtIntrospection: { enabled: true },
  encryption: { enabled: true },
});

export default {
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
    token_endpoint_auth_method: 'none',
    introspection_signed_response_alg: 'HS256',
    redirect_uris: ['https://client.example.com/cb'],
  },
  {
    client_id: 'client-encrypted',
    client_secret: 'secret',
    token_endpoint_auth_method: 'none',
    introspection_encrypted_response_alg: 'A128KW',
    redirect_uris: ['https://client.example.com/cb'],
  }],
};
