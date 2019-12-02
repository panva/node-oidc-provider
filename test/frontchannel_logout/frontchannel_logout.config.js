const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const config = cloneDeep(require('../default.config'));

merge(config.features, {
  frontchannelLogout: { enabled: true },
});

module.exports = {
  config,
  clients: [{
    client_id: 'client',
    client_secret: 'secret',
    response_types: ['code id_token'],
    grant_types: ['implicit', 'authorization_code', 'refresh_token'],
    redirect_uris: ['https://client.example.com/cb'],
    frontchannel_logout_uri: 'https://client.example.com/frontchannel_logout',
    frontchannel_logout_session_required: true,
  }, {
    client_id: 'second-client',
    client_secret: 'secret',
    response_types: ['code id_token'],
    grant_types: ['implicit', 'authorization_code', 'refresh_token'],
    redirect_uris: ['https://second-client.example.com/cb'],
    frontchannel_logout_uri: 'https://second-client.example.com/frontchannel_logout',
    frontchannel_logout_session_required: true,
  }, {
    client_id: 'no-nothing',
    client_secret: 'secret',
    response_types: ['code id_token'],
    grant_types: ['implicit', 'authorization_code', 'refresh_token'],
    redirect_uris: ['https://no-nothing.example.com/cb'],
    frontchannel_logout_uri: 'https://no-nothing.example.com/frontchannel_logout',
    // frontchannel_logout_session_required: false,
  }],
};
