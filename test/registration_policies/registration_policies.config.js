const { clone } = require('lodash');

const config = clone(require('../default.config'));

config.features = {
  registrationManagement: { enabled: true },
  registration: {
    enabled: true,
    initialAccessToken: true,
    policies: {
      'empty-policy': () => {},
    },
  },
};

module.exports = {
  config,
};
