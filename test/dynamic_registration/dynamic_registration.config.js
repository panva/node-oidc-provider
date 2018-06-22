const { clone } = require('lodash');

const config = clone(require('../default.config'));

config.features = { registration: true };

module.exports = {
  config,
};
