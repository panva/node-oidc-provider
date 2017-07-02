const { clone } = require('lodash');
const config = clone(require('../default.config'));

config.features = { oauthNativeApps: true };

module.exports = {
  config,
};
