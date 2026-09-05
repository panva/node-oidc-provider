import { checkSessionBinding, setAttestBinding } from './token_helpers.js';

export default (provider) => class BackchannelAuthenticationRequest extends provider.BaseToken {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'consumed',
      'grantId',
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
      'error',
      'errorDescription',
      'params',
      'rar',
    ];
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

  async setAttestBinding(ctx) {
    await setAttestBinding(this, ctx);
  }
};
