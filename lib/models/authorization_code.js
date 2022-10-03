const apply = require('./mixins/apply');
const consumable = require('./mixins/consumable');
const hasFormat = require('./mixins/has_format');
const hasGrantId = require('./mixins/has_grant_id');
const isSessionBound = require('./mixins/is_session_bound');
const storesAuth = require('./mixins/stores_auth');
const storesPKCE = require('./mixins/stores_pkce');

module.exports = (provider) => class AuthorizationCode extends apply([
  consumable,
  isSessionBound(provider),
  hasGrantId,
  storesAuth,
  storesPKCE,
  hasFormat(provider, 'AuthorizationCode', provider.BaseToken),
]) {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'redirectUri',
    ];
  }
};
