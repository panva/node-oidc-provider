const epochTime = require('../helpers/epoch_time.js');

const apply = require('./mixins/apply.js');
const consumable = require('./mixins/consumable.js');
const hasFormat = require('./mixins/has_format.js');
const hasGrantId = require('./mixins/has_grant_id.js');
const hasGrantType = require('./mixins/has_grant_type.js');
const isSenderConstrained = require('./mixins/is_sender_constrained.js');
const isSessionBound = require('./mixins/is_session_bound.js');
const storesAuth = require('./mixins/stores_auth.js');

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
