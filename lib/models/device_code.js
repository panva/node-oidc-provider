import { strict as assert } from 'node:assert';

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
    try {
      assert(stored);
      assert.equal(userCode, stored.userCode);
      const payload = await this.verify(stored, { ignoreExpiration });
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
