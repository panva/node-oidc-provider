const clone = require('lodash/clone');

const config = clone(require('../default.config'));
const { formats: { AccessToken: FORMAT } } = require('../../lib/helpers/defaults');

config.formats = {
  default: FORMAT,
};

module.exports = {
  config,
};
