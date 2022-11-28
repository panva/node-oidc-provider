const cloneDeep = require('lodash/cloneDeep');

const config = cloneDeep(require('../default.config.js'));

module.exports = {
  config,
};
