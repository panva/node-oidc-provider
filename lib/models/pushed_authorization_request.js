import instance from '../helpers/weak_cache.js';

import { setAttestBinding } from './token_helpers.js';

export default (provider) => class PushedAuthorizationRequest extends instance(provider).BaseModel {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'consumed',
      'attestationJkt',
      'request',
      'dpopJkt',
      'trusted',
    ];
  }

  async consume() {
    await this.adapter.consume(this.jti);
    this.emit('consumed');
  }

  get isValid() {
    return !this.consumed && !this.isExpired;
  }

  async setAttestBinding(ctx) {
    await setAttestBinding(this, ctx);
  }
};
