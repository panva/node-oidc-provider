const { clone } = require('lodash');

const config = clone(require('../default.config'));

config.features = { encryption: { enabled: true } };

module.exports = {
  config,
};
