const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const config = cloneDeep(require('../default.config'));

config.enabledJWA.requestObjectSigningAlgValues = config.enabledJWA.requestObjectSigningAlgValues.filter((alg) => alg !== 'none');

merge(config.features, {
  pushedAuthorizationRequests: {
    allowDynamicRedirectUris: false,
    requirePushedAuthorizationRequests: false,
    enabled: true,
  },
  requestObjects: {
    request: false,
    requestUri: false,
  },
});

module.exports = {
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
  }, {
    client_id: 'client-allow-par-dynamic-redirect',
    client_secret: 'secret',
    redirect_uris: ['https://rp.example.com'],
  }, {
    client_id: 'client-redirect-trailing-slash',
    client_secret: 'secret',
    redirect_uris: ['https://rp.example.com/'],
  },
  ],
};
