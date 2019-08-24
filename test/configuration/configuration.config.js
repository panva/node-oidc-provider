const clone = require('lodash/clone');

const config = clone(require('../default.config'));

config.features = {
  encryption: { enabled: true },
  introspection: { enabled: true },
  jwtIntrospection: { enabled: true },
};

module.exports = {
  config,
};
