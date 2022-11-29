import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, {
  pushedAuthorizationRequests: {
    requirePushedAuthorizationRequests: false,
    enabled: true,
  },
  requestObjects: {
    request: false,
    requestUri: false,
  },
});

export default {
  config,
  clients: [{
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
  }],
};
