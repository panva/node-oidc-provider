const { clone } = require('lodash');

const config = clone(require('../default.config'));

config.features = { registration: { enabled: true } };

module.exports = {
  config,
};
