const { clone } = require('lodash');

const config = clone(require('../default.config'));

config.features = { introspection: true, revocation: true, jwtIntrospection: true };

module.exports = {
  config,
};
