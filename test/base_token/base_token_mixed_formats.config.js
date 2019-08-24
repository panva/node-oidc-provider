const clone = require('lodash/clone');
const sample = require('lodash/sample');
const shuffle = require('lodash/shuffle');

const config = clone(require('../default.config'));
const { formats: { AccessToken: FORMAT } } = require('../../lib/helpers/defaults');

const [AccessToken, RefreshToken, AuthorizationCode] = shuffle(['opaque', 'jwt', 'jwt-ietf', 'paseto', () => sample(['opaque', 'jwt', 'jwt-ietf', 'paseto'])]);

config.formats = {
  default: FORMAT,
  AccessToken,
  RefreshToken,
  AuthorizationCode,
};

module.exports = {
  config,
};
