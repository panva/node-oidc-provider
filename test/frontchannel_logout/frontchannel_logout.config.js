const { clone } = require('lodash');

const config = clone(require('../default.config'));

config.features = { sessionManagement: true, frontchannelLogout: true, alwaysIssueRefresh: true };

module.exports = {
  config,
  clients: [{
    client_id: 'client',
    client_secret: 'secret',
    response_types: ['code id_token'],
    grant_types: ['implicit', 'authorization_code', 'refresh_token'],
    redirect_uris: ['https://client.example.com/cb'],
    frontchannel_logout_uri: 'https://client.example.com/frontchannel_logout',
  }, {
    client_id: 'second-client',
    client_secret: 'secret',
    response_types: ['code id_token'],
    grant_types: ['implicit', 'authorization_code', 'refresh_token'],
    redirect_uris: ['https://second-client.example.com/cb'],
    frontchannel_logout_uri: 'https://second-client.example.com/frontchannel_logout',
  }],
};
