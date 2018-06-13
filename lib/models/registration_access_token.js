const hasFormat = require('./mixins/has_format');

module.exports = function getRegistrationAccessToken(provider) {
  return class RegistrationAccessToken extends hasFormat(provider, 'RegistrationAccessToken', provider.BaseToken) {};
};
