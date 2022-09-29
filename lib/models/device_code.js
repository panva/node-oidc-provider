import constantEquals from '../helpers/constant_equals.js';

import apply from './mixins/apply.js';
import consumable from './mixins/consumable.js';
import hasFormat from './mixins/has_format.js';
import hasGrantId from './mixins/has_grant_id.js';
import isSessionBound from './mixins/is_session_bound.js';
import storesAuth from './mixins/stores_auth.js';

export default (provider) => class DeviceCode extends apply([
  consumable,
  hasGrantId,
  isSessionBound(provider),
  storesAuth,
  hasFormat(provider, 'DeviceCode', provider.BaseToken),
]) {
  static async findByUserCode(userCode, { ignoreExpiration = false } = {}) {
    const stored = await this.adapter.findByUserCode(userCode);
    if (!stored) return undefined;
    try {
      const payload = await this.verify(stored, { ignoreExpiration });
      if (!constantEquals(userCode, payload.userCode)) {
        return undefined;
      }
      return this.instantiate(payload);
    } catch (err) {
      return undefined;
    }
  }

  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'error',
      'errorDescription',
      'params',
      'userCode',
      'inFlight',
      'deviceInfo',
    ];
  }
};
