import instance from '../../helpers/weak_cache.js';
import formatsGenerator from '../formats/index.js';

const CHANGEABLE = new Set(['AccessToken', 'ClientCredentials']);
const DEFAULT = 'opaque';

export default (provider, type, superclass) => {
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
      if (!formats[FORMAT]) throw new TypeError(`unsupported format specified (${FORMAT})`);
      if (FORMAT === 'dynamic') throw new TypeError('dynamic format must be configured as a function');
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
