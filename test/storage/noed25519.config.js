const { clone } = require('lodash');

const config = clone(require('../default.config'));

config.jwks = undefined;

module.exports = {
  config,
};
