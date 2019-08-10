const { strict: assert } = require('assert');

const apply = require('./mixins/apply');
const consumable = require('./mixins/consumable');
const hasFormat = require('./mixins/has_format');
const hasGrantId = require('./mixins/has_grant_id');
const hasGrantType = require('./mixins/has_grant_type');
const isSessionBound = require('./mixins/is_session_bound');
const storesAuth = require('./mixins/stores_auth');
const storesPKCE = require('./mixins/stores_pkce');

module.exports = (provider) => class DeviceCode extends apply([
  consumable,
  hasGrantType,
  hasGrantId,
  isSessionBound(provider),
  storesAuth,
  storesPKCE,
  hasFormat(provider, 'DeviceCode', provider.BaseToken),
]) {
  static async findByUserCode(userCode, { ignoreExpiration = false } = {}) {
    const stored = await this.adapter.findByUserCode(userCode);
    try {
      assert(stored);
      assert.equal(userCode, stored.userCode);
      const payload = await this.verify(undefined, stored, {
        ignoreExpiration, foundByReference: true,
      });
      return new this(payload);
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
