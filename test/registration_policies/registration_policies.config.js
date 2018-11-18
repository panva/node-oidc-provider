const { clone } = require('lodash');

const config = clone(require('../default.config'));

config.features = {
  registrationManagement: true,
  registration: {
    initialAccessToken: true,
    policies: {
      'empty-policy': () => {},
    },
  },
};

module.exports = {
  config,
};
