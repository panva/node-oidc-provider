import epochTime from '../helpers/epoch_time.js';
import instance from '../helpers/weak_cache.js';

import apply from './mixins/apply.js';
import consumable from './mixins/consumable.js';
import hasFormat from './mixins/has_format.js';
import hasGrantId from './mixins/has_grant_id.js';
import hasGrantType from './mixins/has_grant_type.js';
import isSenderConstrained from './mixins/is_sender_constrained.js';
import isAttestationConstrained from './mixins/is_attestation_constrained.js';
import isSessionBound from './mixins/is_session_bound.js';
import storesAuth from './mixins/stores_auth.js';

export default (provider) => class RefreshToken extends apply([
  consumable,
  hasGrantType,
  hasGrantId,
  isSenderConstrained,
  isAttestationConstrained,
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

      'rar',
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

  /*
   * Override isValid to implement grace period for refresh tokens only
   */
  get isValid() {
    const configuration = instance(provider).configuration;
    const gracePeriodSeconds = configuration.refreshTolerance.gracePeriodSeconds;
    
    // Original validation: not consumed and not expired
    if (!this.consumed && !this.isExpired) {
      return true;
    }

    // If no grace period configured, use strict validation
    if (!gracePeriodSeconds || gracePeriodSeconds <= 0) {
      return false;
    }

    // Grace period logic: allow consumed tokens within grace period
    if (this.consumed) {
      const now = epochTime();
      const consumedWithinGrace = (now - this.consumed) < gracePeriodSeconds;
      
      // Token is valid if consumed within grace period AND not expired (including grace period extension)
      return consumedWithinGrace && !this.isExpired;
    }

    // If expired but not consumed, not valid (expired tokens can't benefit from grace period)
    return false;
  }
};
