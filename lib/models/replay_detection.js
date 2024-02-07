import hash from 'object-hash';

import instance from '../helpers/weak_cache.js';
import epochTime from '../helpers/epoch_time.js';
import * as base64url from '../helpers/base64url.js';

import hasFormat from './mixins/has_format.js';

const fingerprint = (properties) => base64url.encodeBuffer(hash(properties, {
  ignoreUnknown: true,
  unorderedArrays: true,
  encoding: 'buffer',
  algorithm: 'sha256',
  respectType: false,
}));

export default (provider) => class ReplayDetection extends hasFormat(provider, 'ReplayDetection', instance(provider).BaseModel) {
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

    const inst = this.instantiate({ jti: id, iss });

    await inst.save(exp - epochTime());

    return true;
  }
};
