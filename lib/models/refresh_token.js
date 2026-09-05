import epochTime from '../helpers/epoch_time.js';

import { checkSessionBinding, setThumbprint, setAttestBinding } from './token_helpers.js';

export default (provider) => class RefreshToken extends provider.BaseToken {
  constructor(...args) {
    super(...args);
    if (!this.iiat) {
      this.iiat = this.iat || epochTime();
    }
  }

  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'consumed',
      'gty',
      'grantId',
      'x5t#S256',
      'jkt',
      'attestationJkt',
      'sessionUid',
      'expiresWithSession',
      'accountId',
      'acr',
      'amr',
      'authTime',
      'claims',
      'nonce',
      'resource',
      'scope',
      'sid',
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

  async consume() {
    await this.adapter.consume(this.jti);
    this.emit('consumed');
  }

  get isValid() {
    return !this.consumed && !this.isExpired;
  }

  static async find(...args) {
    return checkSessionBinding(provider, await super.find(...args), args[1]);
  }

  static async revokeByGrantId(grantId) {
    await this.adapter.revokeByGrantId(grantId);
  }

  setThumbprint(prop, input) {
    setThumbprint(this, prop, input);
  }

  isSenderConstrained() {
    return !!(this.jkt || this['x5t#S256']);
  }

  get tokenType() {
    return this.jkt ? 'DPoP' : 'Bearer';
  }

  async setAttestBinding(ctx) {
    await setAttestBinding(this, ctx);
  }
};
