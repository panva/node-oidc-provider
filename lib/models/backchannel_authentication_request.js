const apply = require('./mixins/apply');
const consumable = require('./mixins/consumable');
const hasFormat = require('./mixins/has_format');
const hasGrantId = require('./mixins/has_grant_id');
const isSessionBound = require('./mixins/is_session_bound');
const storesAuth = require('./mixins/stores_auth');

module.exports = (provider) => class BackchannelAuthenticationRequest extends apply([
  consumable,
  hasGrantId,
  isSessionBound(provider),
  storesAuth,
  hasFormat(provider, 'BackchannelAuthenticationRequest', provider.BaseToken),
]) {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'error',
      'errorDescription',
      'params',
    ];
  }
};
