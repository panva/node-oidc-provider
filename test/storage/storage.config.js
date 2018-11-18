const { clone } = require('lodash');

const config = clone(require('../default.config'));

config.features = {};
config.features.registration = {
  initialAccessToken: true,
  policies: {
    foo() {},
  },
};

module.exports = {
  config,
  clients: [{
    client_id: 'client',
    client_secret: 'secret',
    redirect_uris: ['https://client.example.com/cb'],
  }],
};
