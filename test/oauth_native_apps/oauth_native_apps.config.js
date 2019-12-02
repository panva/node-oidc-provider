const cloneDeep = require('lodash/cloneDeep');

const config = cloneDeep(require('../default.config'));

module.exports = {
  config,
};
