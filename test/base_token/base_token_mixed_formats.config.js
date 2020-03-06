const cloneDeep = require('lodash/cloneDeep');
const sample = require('lodash/sample');
const shuffle = require('lodash/shuffle');

const config = cloneDeep(require('../default.config'));

const { formats: { AccessToken: FORMAT } } = global.TEST_CONFIGURATION_DEFAULTS;

const [AccessToken, RefreshToken, AuthorizationCode] = shuffle(['opaque', 'jwt', 'jwt-ietf', () => sample(['opaque', 'jwt', 'jwt-ietf'])]);

config.formats = {
  default: FORMAT,
  AccessToken,
  RefreshToken,
  AuthorizationCode,
};

module.exports = {
  config,
};
