const clone = require('lodash/clone');

const config = clone(require('../default.config'));

config.jwks = undefined;

module.exports = {
  config,
};
