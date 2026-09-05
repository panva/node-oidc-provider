import { generateTokenId, getValueAndPayload } from './formats/index.js';
import { checkSessionBinding, setThumbprint, setAudience } from './token_helpers.js';

export default (provider) => class AccessToken extends provider.BaseToken {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'gty',
      'grantId',
      'x5t#S256',
      'jkt',
      'sessionUid',
      'expiresWithSession',
      'accountId',
      'aud',
      'rar',
      'claims',
      'extra',
      'grantId',
      'scope',
      'sid',
    ];
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

  setAudience(audience) {
    setAudience(this, audience);
  }

  generateTokenId() {
    return generateTokenId(provider, this);
  }

  async getValueAndPayload() {
    return getValueAndPayload(provider, this);
  }
};
