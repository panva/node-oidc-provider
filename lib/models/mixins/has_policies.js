import instance from '../../helpers/weak_cache.js';

function validate(provider, policies) {
  if (!Array.isArray(policies)) {
    throw new TypeError('policies must be an array');
  }
  if (!policies.length) {
    throw new TypeError('policies must not be empty');
  }
  policies.forEach((policy) => {
    if (typeof policy !== 'string') {
      throw new TypeError('policies must be strings');
    }
    if (!instance(provider).configuration(`features.registration.policies.${policy}`)) {
      throw new TypeError(`policy ${policy} not configured`);
    }
  });
}

export default (provider) => (superclass) => class extends superclass {
  async save() {
    if (typeof this.policies !== 'undefined') validate(provider, this.policies);
    return super.save();
  }

  static async find(...args) {
    const result = await super.find(...args);
    if (result && typeof result.policies !== 'undefined') validate(provider, result.policies);
    return result;
  }

  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'policies',
    ];
  }
};
