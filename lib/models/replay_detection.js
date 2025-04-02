import * as crypto from 'node:crypto';

import instance from '../helpers/weak_cache.js';
import epochTime from '../helpers/epoch_time.js';

import hasFormat from './mixins/has_format.js';

export default (provider) => class ReplayDetection extends hasFormat(provider, 'ReplayDetection', instance(provider).BaseModel) {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'iss',
    ];
  }

  static async unique(iss, jti, exp) {
    const id = crypto.hash('sha256', `${iss}${jti}`, 'base64url');

    const found = await this.find(id);

    if (found) {
      return false;
    }

    const inst = this.instantiate({ jti: id, iss });

    await inst.save(exp - epochTime());

    return true;
  }
};
