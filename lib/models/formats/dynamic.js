const instance = require('../../helpers/weak_cache');
const ctxRef = require('../ctx_ref');

module.exports = (provider, formats) => ({
  generateTokenId(...args) {
    const resolver = instance(provider).dynamic[this.constructor.name];
    const format = resolver(ctxRef.get(this), this);
    if (!formats[format] || format === 'dynamic') {
      throw new Error('invalid format resolved');
    }
    this.format = format;
    return formats[format].generateTokenId.apply(this, args);
  },
  async getValueAndPayload(...args) {
    const { format } = this;
    if (!formats[format] || format === 'dynamic') {
      throw new Error('invalid format resolved');
    }
    return formats[format].getValueAndPayload.apply(this, args);
  },
});
