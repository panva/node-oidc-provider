const { strict: assert } = require('assert');

const instance = require('../../helpers/weak_cache');
const formatsGenerator = require('../formats');

const CHANGEABLE = new Set(['AccessToken', 'ClientCredentials']);
const DEFAULT = 'opaque';

module.exports = (provider, type, superclass) => {
  const config = instance(provider).configuration('formats');
  const formats = formatsGenerator(provider);

  let { [type]: FORMAT } = config;

  // only allow AccessToken and ClientCredentials to be defined by developers
  if (!CHANGEABLE.has(type)) {
    FORMAT = DEFAULT;
  }

  if (FORMAT !== DEFAULT || type === 'base') {
    const dynamic = typeof FORMAT === 'function';
    if (!dynamic) {
      assert(formats[FORMAT], `unsupported format specified (${FORMAT})`);
      assert(FORMAT !== 'dynamic', 'dynamic format must be configured as a function');
    }

    const {
      generateTokenId,
      getValueAndPayload,
    } = formats[dynamic ? 'dynamic' : FORMAT];

    const klass = class extends superclass {};
    klass.prototype.generateTokenId = generateTokenId;
    klass.prototype.getValueAndPayload = getValueAndPayload;
    klass.prototype.constructor.verify = formats.opaque.verify;

    if (dynamic) {
      instance(provider).dynamic = instance(provider).dynamic || {};
      instance(provider).dynamic[type] = FORMAT;
    }

    return klass;
  }

  return superclass;
};
