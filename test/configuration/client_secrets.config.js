const clone = require('lodash/clone');

const config = clone(require('../default.config'));

config.features = {
  introspection: { enabled: true },
  revocation: { enabled: true },
  jwtIntrospection: { enabled: true },
};

module.exports = {
  config,
};
