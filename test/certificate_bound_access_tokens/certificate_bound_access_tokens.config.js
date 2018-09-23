const { clone } = require('lodash');

const config = clone(require('../default.config'));

config.features = {
  certificateBoundAccessTokens: true,
  clientCredentials: true,
  introspection: true,
  alwaysIssueRefresh: true,
  revocation: true,
  deviceFlow: true,
};

module.exports = {
  config,
  client: {
    client_id: 'client',
    grant_types: [
      'authorization_code',
      'refresh_token',
      'urn:ietf:params:oauth:grant-type:device_code',
      'client_credentials',
    ],
    response_types: ['code'],
    redirect_uris: ['https://client.example.com/cb'],
    token_endpoint_auth_method: 'none',
    tls_client_certificate_bound_access_tokens: true,
  },
};
