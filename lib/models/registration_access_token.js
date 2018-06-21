const hasFormat = require('./mixins/has_format');

module.exports = provider => class RegistrationAccessToken extends hasFormat(
  provider,
  'RegistrationAccessToken',
  provider.BaseToken,
) {};
