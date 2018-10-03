const { cloneDeep, pull } = require('lodash');

const config = cloneDeep(require('../default.config'));

config.features = {
  request: true,
  requestUri: { requireRequestUriRegistration: false },
  claimsParameter: true,
  deviceFlow: true,
  resourceIndicators: true,
};

pull(config.whitelistedJWA.requestObjectSigningAlgValues, 'HS384');

module.exports = {
  config,
  clients: [{
    client_id: 'client',
    client_secret: 'its48bytes_____________________________________!',
    grant_types: ['urn:ietf:params:oauth:grant-type:device_code', 'authorization_code'],
    redirect_uris: ['https://client.example.com/cb'],
  }, {
    client_id: 'client-with-HS-sig',
    client_secret: 'atleast32byteslongforHS256mmkay?',
    request_object_signing_alg: 'HS256',
    grant_types: ['urn:ietf:params:oauth:grant-type:device_code', 'authorization_code'],
    redirect_uris: ['https://client.example.com/cb'],
  }],
};
