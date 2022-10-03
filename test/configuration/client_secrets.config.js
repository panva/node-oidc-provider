const cloneDeep = require('lodash/cloneDeep');
const merge = require('lodash/merge');

const config = cloneDeep(require('../default.config'));

merge(config.features, {
  introspection: { enabled: true },
  revocation: { enabled: true },
  jwtIntrospection: { enabled: true },
});

module.exports = {
  config,
};
