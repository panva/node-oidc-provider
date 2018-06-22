const { clone, shuffle } = require('lodash');

const config = clone(require('../default.config'));
const { formats: { default: FORMAT } } = require('../../lib/helpers/defaults');
const [AccessToken, RefreshToken, AuthorizationCode] = shuffle(Object.keys(require('../../lib/models/formats')));

config.formats = {
  default: FORMAT,
  AccessToken,
  RefreshToken,
  AuthorizationCode,
};

module.exports = {
  config,
};
