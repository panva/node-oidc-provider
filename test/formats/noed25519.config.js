const cloneDeep = require('lodash/cloneDeep');

const config = cloneDeep(require('../default.config'));

config.jwks = undefined;

module.exports = {
  config,
};
