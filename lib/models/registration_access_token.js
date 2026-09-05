import { validatePolicies } from './token_helpers.js';

export default (provider) => class RegistrationAccessToken extends provider.BaseToken {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'policies',
    ];
  }

  async save() {
    if (typeof this.policies !== 'undefined') validatePolicies(provider, this.policies);
    return super.save();
  }

  static async find(...args) {
    const result = await super.find(...args);
    if (result && typeof result.policies !== 'undefined') validatePolicies(provider, result.policies);
    return result;
  }
};
