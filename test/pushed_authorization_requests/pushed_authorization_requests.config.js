import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

config.extraParams = {
  extra: null,
  extra2(ctx) {
    ctx.oidc.params.extra2 ||= 'defaulted';
  },
};

merge(config.features, {
  pushedAuthorizationRequests: {
    requirePushedAuthorizationRequests: false,
    enabled: true,
    allowUnregisteredRedirectUris: false,
  },
  claimsParameter: {
    enabled: true,
  },
});

function allowUnregisteredClient(suffix, metadata) {
  return {
    client_id: `client-unregistered-test-${suffix}`,
    application_type: 'web',
    token_endpoint_auth_method: 'client_secret_basic',
    client_secret: 'secret',
    redirect_uris: ['https://rp.example.com/cb'],
    ...metadata,
  };
}

export default {
  config,
  clients: [
    {
      client_id: 'client',
      client_secret: 'secret',
      redirect_uris: ['https://rp.example.com/cb'],
    }, {
      client_id: 'client-par-required',
      client_secret: 'secret',
      redirect_uris: ['https://rp.example.com/cb'],
      require_pushed_authorization_requests: true,
    }, {
      client_id: 'client-alg-registered',
      client_secret: 'secret',
      request_object_signing_alg: 'HS256',
      redirect_uris: ['https://rp.example.com/cb'],
    },
    allowUnregisteredClient('public', { token_endpoint_auth_method: 'none' }),
  ],
};
