const { clone } = require('lodash');

const config = clone(require('../default.config'));

config.features = {
  encryption: true,
  introspection: true,
  jwtIntrospection: true,
};

module.exports = {
  config,
};
