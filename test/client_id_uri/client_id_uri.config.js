const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const nanoid = require('../../lib/helpers/nanoid');
const config = cloneDeep(require('../default.config'));

merge(config.features, {
  registration: {
    enabled: true,
    rotateRegistrationAccessToken: false,
    idFactory() {
      return new URL(`https://repo.clients.com/path?id=${nanoid()}`).href;
    },
  },
  registrationManagement: {
    enabled: true,
  },
});

module.exports = {
  config,
};
