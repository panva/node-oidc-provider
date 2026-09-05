import { generateTokenId, getValueAndPayload } from './formats/index.js';
import { setThumbprint, setAudience } from './token_helpers.js';

export default (provider) => class ClientCredentials extends provider.BaseToken {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'x5t#S256',
      'jkt',
      'aud',
      'extra',
      'rar',
      'scope',
    ];
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
