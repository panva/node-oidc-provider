const assert = require('assert');

const apply = require('./mixins/apply');
const consumable = require('./mixins/consumable');
const hasFormat = require('./mixins/has_format');
const hasGrantType = require('./mixins/has_grant_type');
const storesAuth = require('./mixins/stores_auth');
const storesPKCE = require('./mixins/stores_pkce');

module.exports = provider => class DeviceCode extends apply([
  storesPKCE,
  storesAuth,
  consumable(provider),
  hasGrantType,
  hasFormat(provider, 'DeviceCode', provider.BaseToken),
]) {
  static async findByUserCode(userCode, { ignoreExpiration = false } = {}) {
    let rethrow;
    try {
      const stored = await this.adapter.findByUserCode(userCode).catch((err) => {
        rethrow = true;
        throw err;
      });
      assert(stored);
      assert.deepEqual(userCode, stored.userCode);
      const payload = await this.verify(undefined, stored, {
        ignoreExpiration, foundByUserCode: true,
      });
      const inst = new this(payload);

      return inst;
    } catch (err) {
      if (rethrow) throw err;
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
      'deviceInfo',
    ];
  }
};
