const { strict: assert } = require('assert');

const JWT = require('../../helpers/jwt');
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
    if (value && (value.length === 27 || value.length === 43)) {
      format = 'opaque';
    } else if (value.startsWith('v2.public.')) {
      format = 'paseto';
    } else if (JWT_REGEX.test(value)) {
      if (JWT.header(value).typ === 'at+jwt') {
        format = 'jwt-ietf';
      } else {
        format = 'jwt';
      }
    } else {
      format = 'opaque';
    }
    assert(formats[format] && format !== 'dynamic', 'invalid format resolved');
    return formats[format].getTokenId.apply(this, args);
  },
  async verify(...args) {
    const format = args[1].format || (args[1].jwt ? 'jwt' : args[1]['jwt-ietf'] ? 'jwt-ietf' : args[1].paseto ? 'paseto' : 'opaque'); // eslint-disable-line no-nested-ternary
    assert(formats[format] && format !== 'dynamic', 'invalid format resolved');
    return formats[format].verify.apply(this, args);
  },
});
