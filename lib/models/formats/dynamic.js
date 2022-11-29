import { strict as assert } from 'node:assert';

import instance from '../../helpers/weak_cache.js';
import ctxRef from '../ctx_ref.js';

export default (provider, formats) => ({
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
});
