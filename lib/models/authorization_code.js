const storesPKCE = require('./mixins/stores_pkce');
const storesAuth = require('./mixins/stores_auth');

module.exports = function getAuthorizationCode({ BaseToken }) {
  return class AuthorizationCode extends storesAuth(storesPKCE(BaseToken)) {
    static get IN_PAYLOAD() {
      return [
        ...super.IN_PAYLOAD,
        'redirectUri',
      ];
    }
  };
};
