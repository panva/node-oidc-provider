const { clone } = require('lodash');

const config = clone(require('../default.config'));

config.features = { backchannelLogout: { enabled: true } };

module.exports = {
  config,
  clients: [{
    client_id: 'client',
    client_secret: 'secret',
    response_types: ['code id_token'],
    grant_types: ['implicit', 'authorization_code', 'refresh_token'],
    redirect_uris: ['https://client.example.com/cb'],
    backchannel_logout_uri: 'https://client.example.com/backchannel_logout',
    backchannel_logout_session_required: true,
  }, {
    client_id: 'second-client',
    client_secret: 'secret',
    response_types: ['code id_token'],
    grant_types: ['implicit', 'authorization_code', 'refresh_token'],
    redirect_uris: ['https://second-client.example.com/cb'],
    backchannel_logout_uri: 'https://second-client.example.com/backchannel_logout',
    backchannel_logout_session_required: true,
  }],
};
