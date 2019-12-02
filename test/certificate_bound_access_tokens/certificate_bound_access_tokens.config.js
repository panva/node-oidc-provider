const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const config = cloneDeep(require('../default.config'));

merge(config.features, {
  mTLS: {
    enabled: true,
    certificateBoundAccessTokens: true,
    getCertificate(ctx) {
      return ctx.get('x-ssl-client-cert');
    },
  },
  clientCredentials: { enabled: true },
  introspection: { enabled: true },
  deviceFlow: { enabled: true },
});

module.exports = {
  config,
  clients: [
    {
      client_id: 'client',
      client_secret: 'secret',
      grant_types: [
        'authorization_code',
        'refresh_token',
        'urn:ietf:params:oauth:grant-type:device_code',
        'client_credentials',
      ],
      response_types: ['code'],
      redirect_uris: ['https://client.example.com/cb'],
      tls_client_certificate_bound_access_tokens: true,
    },
    {
      client_id: 'client-none',
      grant_types: [
        'authorization_code',
        'urn:ietf:params:oauth:grant-type:device_code',
        'refresh_token',
      ],
      response_types: ['code'],
      redirect_uris: ['https://client.example.com/cb'],
      token_endpoint_auth_method: 'none',
      tls_client_certificate_bound_access_tokens: true,
    },
  ],
};
