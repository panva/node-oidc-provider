const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const config = cloneDeep(require('../default.config'));

config.whitelistedJWA.requestObjectSigningAlgValues = config.whitelistedJWA.requestObjectSigningAlgValues.filter((alg) => alg !== 'none');

merge(config.features, {
  pushedAuthorizationRequests: {
    requirePushedAuthorizationRequests: false,
    enabled: true,
  },
  requestObjects: {
    request: true,
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
  }],
};
