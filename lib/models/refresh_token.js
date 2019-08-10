const epochTime = require('../helpers/epoch_time');

const apply = require('./mixins/apply');
const consumable = require('./mixins/consumable');
const hasFormat = require('./mixins/has_format');
const hasGrantId = require('./mixins/has_grant_id');
const hasGrantType = require('./mixins/has_grant_type');
const isSenderConstrained = require('./mixins/is_sender_constrained');
const isSessionBound = require('./mixins/is_session_bound');
const storesAuth = require('./mixins/stores_auth');

module.exports = (provider) => class RefreshToken extends apply([
  consumable,
  hasGrantType,
  hasGrantId,
  isSenderConstrained,
  isSessionBound(provider),
  storesAuth,
  hasFormat(provider, 'RefreshToken', provider.BaseToken),
]) {
  constructor(...args) {
    super(...args);
    if (!this.iiat) {
      this.iiat = this.iat || epochTime();
    }
  }

  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,

      'rotations',
      'iiat',
    ];
  }

  /*
   * totalLifetime()
   * number of seconds since the very first refresh token chain iat
   */
  totalLifetime() {
    return epochTime() - this.iiat;
  }
};
