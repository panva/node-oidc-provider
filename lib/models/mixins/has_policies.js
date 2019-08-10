const { strict: assert } = require('assert');

const instance = require('../../helpers/weak_cache');

function validate(provider, policies) {
  assert(Array.isArray(policies), 'policies must be an array');
  assert(policies.length, 'policies must not be empty');
  policies.forEach((policy) => {
    assert(typeof policy === 'string', 'policies must be strings');
    assert(instance(provider).configuration(`features.registration.policies.${policy}`), `policy ${policy} not configured`);
  });
}

module.exports = (provider) => (superclass) => class extends superclass {
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
