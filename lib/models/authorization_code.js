const apply = require('./mixins/apply.js');
const consumable = require('./mixins/consumable.js');
const hasFormat = require('./mixins/has_format.js');
const hasGrantId = require('./mixins/has_grant_id.js');
const isSessionBound = require('./mixins/is_session_bound.js');
const storesAuth = require('./mixins/stores_auth.js');
const storesPKCE = require('./mixins/stores_pkce.js');

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
      'dpopJkt',
    ];
  }
};
