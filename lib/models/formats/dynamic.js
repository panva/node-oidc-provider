const { strict: assert } = require('assert');

const instance = require('../../helpers/weak_cache');
const ctxRef = require('../ctx_ref');

const JWT_REGEX = /^(?:[a-zA-Z0-9-_]+\.){2}[a-zA-Z0-9-_]+$/;

module.exports = (provider, formats) => ({
  generateTokenId(...args) {
    const resolver = instance(provider).dynamic[this.constructor.name];
    const format = resolver(ctxRef.get(this), this);
    assert(formats[format] && format !== 'dynamic', 'invalid format resolved');
    this.format = format;
    return formats[format].generateTokenId.apply(this, args);
  },
  async getValueAndPayload(...args) {
    const { format } = this;
    assert(formats[format] && format !== 'dynamic', 'invalid format resolved');
    return formats[format].getValueAndPayload.apply(this, args);
  },
  getTokenId(...args) {
    let format;
    const [value] = args;
    if (JWT_REGEX.test(value)) {
      // get tokenId is the same for jwt and jwt-ietf
      format = 'jwt';
    } else {
      format = 'opaque';
    }
    assert(formats[format] && format !== 'dynamic', 'invalid format resolved');
    return formats[format].getTokenId.apply(this, args);
  },
  async verify(...args) {
    const { format } = args[0];
    assert(formats[format] && format !== 'dynamic', 'invalid format resolved');
    return formats[format].verify.apply(this, args);
  },
});
