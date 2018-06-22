const { clone } = require('lodash');

const config = clone(require('../default.config'));

config.features = { encryption: true };

module.exports = {
  config,
};
