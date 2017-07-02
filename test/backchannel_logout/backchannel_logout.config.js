const { clone } = require('lodash');
const config = clone(require('../default.config'));

config.features = { sessionManagement: true, backchannelLogout: true, alwaysIssueRefresh: true };

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    response_types: ['code id_token'],
    grant_types: ['implicit', 'authorization_code', 'refresh_token'],
    redirect_uris: ['https://client.example.com/cb'],
    backchannel_logout_uri: 'https://client.example.com/backchannel_logout'
  },
};
