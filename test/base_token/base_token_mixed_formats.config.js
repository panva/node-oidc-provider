const { clone, sample, shuffle } = require('lodash');

const config = clone(require('../default.config'));
const { formats: { default: FORMAT } } = require('../../lib/helpers/defaults');

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
