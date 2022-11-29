import apply from './mixins/apply.js';
import consumable from './mixins/consumable.js';
import hasFormat from './mixins/has_format.js';
import hasGrantId from './mixins/has_grant_id.js';
import isSessionBound from './mixins/is_session_bound.js';
import storesAuth from './mixins/stores_auth.js';
import storesPKCE from './mixins/stores_pkce.js';

export default (provider) => class AuthorizationCode extends apply([
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
