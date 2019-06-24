const assert = require('assert');

const formats = require('../formats');
const instance = require('../../helpers/weak_cache');

const CHANGEABLE = new Set(['AccessToken', 'ClientCredentials']);

module.exports = (provider, type, superclass) => {
  const config = instance(provider).configuration('formats');

  let { [type]: FORMAT } = config;
  let { default: DEFAULT = 'opaque' } = config;

  if (type === 'Session' || type === 'Interaction' || type === 'ReplayDetection') {
    FORMAT = 'opaque';
  }

  // only allow AccessToken and ClientCredentials to be defined by users
  /* istanbul ignore if */
  if (process.env.NODE_ENV !== 'test') {
    DEFAULT = 'opaque';
    if (!CHANGEABLE.has(type)) {
      FORMAT = 'opaque';
    }
  }

  if ((FORMAT && FORMAT !== DEFAULT) || type === 'default') {
    const dynamic = typeof FORMAT === 'function';
    if (!dynamic) {
      assert(formats[FORMAT], `invalid format specified (${FORMAT})`);
    }

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

    const { IN_PAYLOAD } = klass.prototype.constructor;
    Object.defineProperties(klass.prototype.constructor, {
      format: { value: dynamic ? 'dynamic' : FORMAT },
      ...(FORMAT === 'jwt' ? { IN_PAYLOAD: { value: [...IN_PAYLOAD, 'jwt'] } } : undefined),
      ...(FORMAT === 'paseto' ? { IN_PAYLOAD: { value: [...IN_PAYLOAD, 'paseto'] } } : undefined),
      ...(dynamic ? { IN_PAYLOAD: { value: [...IN_PAYLOAD, 'format', 'jwt', 'paseto'] } } : undefined),
    });

    return klass;
  }

  if (!FORMAT && typeof DEFAULT === 'function') {
    instance(provider).dynamic[type] = DEFAULT;
  }

  return superclass;
};
