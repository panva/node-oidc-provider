const storesAuth = require('./mixins/stores_auth');
const hasFormat = require('./mixins/has_format');

module.exports = function getRefreshToken(provider) {
  return class RefreshToken extends storesAuth(hasFormat(provider, 'RefreshToken', provider.BaseToken)) {};
};
