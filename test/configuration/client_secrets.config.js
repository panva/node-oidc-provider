const { clone } = require('lodash');

const config = clone(require('../default.config'));

config.features = {
  introspection: { enabled: true },
  revocation: { enabled: true },
  jwtIntrospection: { enabled: true },
};

module.exports = {
  config,
};
