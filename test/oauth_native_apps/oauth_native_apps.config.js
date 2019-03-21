const { clone } = require('lodash');

const config = clone(require('../default.config'));

module.exports = {
  config,
};
