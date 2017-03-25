const _ = require('lodash');
const config = _.clone(require('../default.config'));

config.features = { registrationManagement: true, registration: true };

module.exports = {
  config,
  client: {
    client_id: 'client',
    client_secret: 'secret',
    redirect_uris: ['https://client.example.com/cb'],
  }
};
