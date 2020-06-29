const cloneDeep = require('lodash/cloneDeep');

const config = cloneDeep(require('../default.config'));

const { formats: { AccessToken: FORMAT } } = global.TEST_CONFIGURATION_DEFAULTS;

config.formats = {
  default: FORMAT,
};

module.exports = {
  config,
};
