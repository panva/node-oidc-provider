const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const config = cloneDeep(require('../default.config'));

merge(config.features, {
  registrationManagement: { enabled: true },
  registration: {
    enabled: true,
    initialAccessToken: true,
    policies: {
      'empty-policy': () => {},
    },
  },
});

module.exports = {
  config,
};
