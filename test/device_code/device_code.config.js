const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const config = cloneDeep(require('../default.config'));

merge(config.features, {
  deviceFlow: { enabled: true },
  backchannelLogout: { enabled: true },
  claimsParameter: { enabled: true },
  requestObjects: { request: false, requestUri: false },
  resourceIndicators: { enabled: true },
  rpInitiatedLogout: { enabled: false },
});

config.extraParams = [
  'extra',
];

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
    }, {
      client_id: 'client-backchannel',
      grant_types: ['urn:ietf:params:oauth:grant-type:device_code', 'refresh_token'],
      response_types: [],
      redirect_uris: [],
      token_endpoint_auth_method: 'none',
      application_type: 'native',
      backchannel_logout_uri: 'https://rp.example.com/backchannel',
      backchannel_logout_session_required: true,
    }, {
      client_id: 'client-basic-auth',
      client_secret: 'secret',
      grant_types: ['urn:ietf:params:oauth:grant-type:device_code'],
      response_types: [],
      redirect_uris: [],
      token_endpoint_auth_method: 'client_secret_basic',
      application_type: 'native',
    },
  ],
};
