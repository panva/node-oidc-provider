const hash = require('object-hash');

const instance = require('../helpers/weak_cache');
const epochTime = require('../helpers/epoch_time');
const base64url = require('../helpers/base64url');

const hasFormat = require('./mixins/has_format');

const fingerprint = (properties) => base64url.encodeBuffer(hash(properties, {
  ignoreUnknown: true,
  unorderedArrays: true,
  encoding: 'buffer',
  algorithm: 'sha256',
}));

module.exports = (provider) => class ReplayDetection extends hasFormat(provider, 'ReplayDetection', instance(provider).BaseModel) {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'iss',
    ];
  }

  static async unique(iss, jti, exp) {
    const id = fingerprint({ iss, jti });

    const found = await this.find(id);

    if (found) {
      return false;
    }

    const inst = new this({
      jti: id,
      iss,
    });

    await inst.save(exp - epochTime());

    return true;
  }
};
