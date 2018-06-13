const storesPKCE = require('./mixins/stores_pkce');
const storesAuth = require('./mixins/stores_auth');
const hasFormat = require('./mixins/has_format');

module.exports = function getAuthorizationCode(provider) {
  return class AuthorizationCode extends storesAuth(storesPKCE(hasFormat(provider, 'AuthorizationCode', provider.BaseToken))) {
    static get IN_PAYLOAD() {
      return [
        ...super.IN_PAYLOAD,
        'redirectUri',
      ];
    }
  };
};
