const cloneDeep = require('lodash/cloneDeep');

const config = cloneDeep(require('../default.config'));
const { formats: { AccessToken: FORMAT } } = require('../../lib/helpers/defaults');

config.formats = {
  default: FORMAT,
};

module.exports = {
  config,
};
