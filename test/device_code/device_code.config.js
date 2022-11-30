import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, {
  deviceFlow: { enabled: true },
  backchannelLogout: { enabled: true },
  claimsParameter: { enabled: true },
  requestObjects: { request: false, requestUri: true },
  rpInitiatedLogout: { enabled: false },
  pushedAuthorizationRequests: { enabled: false },
});

config.extraParams = [
  'extra',
];

export default {
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
