const { clone } = require('lodash');

const config = clone(require('../default.config'));

config.features = {
  deviceFlow: true,
  request: false,
  claimsParameter: true,
  requestUri: false,
  resourceIndicators: true,
};

config.extraParams = [
  'extra',
];

config.interactionCheck = () => {};

module.exports = {
  config,
  clients: [
    {
      client_id: 'client',
      grant_types: ['urn:ietf:params:oauth:grant-type:device_code', 'refresh_token'],
      response_types: [],
      redirect_uris: [],
      token_endpoint_auth_method: 'none',
      application_type: 'native',
    }, {
      client_id: 'client-other',
      grant_types: ['urn:ietf:params:oauth:grant-type:device_code', 'refresh_token'],
      response_types: [],
      redirect_uris: [],
      token_endpoint_auth_method: 'none',
      application_type: 'native',
    }, {
      client_id: 'client-not-allowed',
      token_endpoint_auth_method: 'none',
      grant_types: [],
      redirect_uris: [],
      response_types: [],
    },
  ],
};
