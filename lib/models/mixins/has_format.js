const assert = require('assert');
const { deprecate } = require('util');

const formats = require('../formats');
const instance = require('../../helpers/weak_cache');

const deprecated = deprecate(() => {}, '"legacy" format is deprecated and will be removed in the next major version');

module.exports = (provider, type, superclass) => {
  const { [type]: FORMAT, default: DEFAULT } = instance(provider).configuration('formats');

  if ((FORMAT && FORMAT !== DEFAULT) || type === 'default') {
    const dynamic = typeof FORMAT === 'function';
    if (!dynamic) {
      assert(formats[FORMAT], `invalid format specified (${FORMAT})`);
    }

    if (FORMAT === 'legacy') deprecated();

    const {
      generateTokenId,
      getValueAndPayload,
      getTokenId,
      verify,
    } = formats[dynamic ? 'dynamic' : FORMAT](provider);

    const klass = class extends superclass {};
    klass.prototype.generateTokenId = generateTokenId;
    klass.prototype.getValueAndPayload = getValueAndPayload;
    klass.prototype.constructor.getTokenId = getTokenId;
    klass.prototype.constructor.verify = verify;

    if (dynamic) {
      instance(provider).dynamic = instance(provider).dynamic || {};
      instance(provider).dynamic[type] = FORMAT;
    }

    Object.defineProperty(klass.prototype.constructor, 'format', { value: dynamic ? 'dynamic' : FORMAT });

    return klass;
  }

  if (!FORMAT && typeof DEFAULT === 'function') {
    instance(provider).dynamic[type] = DEFAULT;
  }

  return superclass;
};
