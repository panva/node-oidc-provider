const assert = require('assert');

const formats = require('../formats');
const instance = require('../../helpers/weak_cache');

module.exports = (provider, type, superclass) => {
  const { [type]: FORMAT, default: DEFAULT } = instance(provider).configuration('formats');

  if ((FORMAT && FORMAT !== DEFAULT) || type === 'default') {
    assert(formats[FORMAT], `invalid format specified (${FORMAT})`);
    const {
      generateTokenId,
      getValueAndPayload,
      getTokenId,
      verify,
    } = formats[FORMAT](provider);

    const klass = class extends superclass {};
    klass.prototype.constructor.generateTokenId = generateTokenId;
    klass.prototype.getValueAndPayload = getValueAndPayload;
    klass.prototype.constructor.getTokenId = getTokenId;
    klass.prototype.constructor.verify = verify;

    Object.defineProperty(klass.prototype.constructor, 'format', { value: FORMAT });

    return klass;
  }

  return superclass;
};
