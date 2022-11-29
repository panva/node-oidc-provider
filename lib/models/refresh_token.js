import epochTime from '../helpers/epoch_time.js';

import apply from './mixins/apply.js';
import consumable from './mixins/consumable.js';
import hasFormat from './mixins/has_format.js';
import hasGrantId from './mixins/has_grant_id.js';
import hasGrantType from './mixins/has_grant_type.js';
import isSenderConstrained from './mixins/is_sender_constrained.js';
import isSessionBound from './mixins/is_session_bound.js';
import storesAuth from './mixins/stores_auth.js';

export default (provider) => class RefreshToken extends apply([
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
