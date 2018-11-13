const apply = require('./mixins/apply');
const consumable = require('./mixins/consumable');
const hasFormat = require('./mixins/has_format');
const storesAuth = require('./mixins/stores_auth');
const storesPKCE = require('./mixins/stores_pkce');

module.exports = provider => class AuthorizationCode extends apply([
  consumable(provider),
  storesPKCE,
  storesAuth,
  hasFormat(provider, 'AuthorizationCode', provider.BaseToken),
]) {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'redirectUri',
    ];
  }
};
