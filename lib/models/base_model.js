const IN_PAYLOAD = [
  'iat',
  'exp',
  'jti',
  'kind',
];

const assert = require('assert');

const { snakeCase, pickBy } = require('lodash');

const instance = require('../helpers/weak_cache');

const hasFormat = require('./mixins/has_format');

const adapterCache = new WeakMap();

module.exports = function getBaseToken(provider) {
  function adapter(ctx) {
    const obj = typeof ctx === 'function' ? ctx : ctx.constructor;

    if (!adapterCache.has(obj)) {
      adapterCache.set(obj, new (instance(provider).Adapter)(obj.name));
    }

    return adapterCache.get(obj);
  }

  class Class {
    constructor({ jti, kind, ...payload } = {}) {
      Object.assign(this, pickBy(
        payload,
        (val, key) => this.constructor.IN_PAYLOAD.includes(key),
      ));

      assert(!kind || kind === this.constructor.name, 'kind mismatch');

      this.kind = kind || this.constructor.name;
      this.jti = jti;
    }

    async save(ttl) {
      if (!this.jti) {
        this.jti = this.generateTokenId();
      }
      const [token, upsert] = await this.getValueAndPayload();

      await this.adapter.upsert(this.jti, upsert, ttl);
      this.emit('saved');

      return token;
    }

    async destroy() {
      await this.adapter.destroy(this.jti);
      this.emit('destroyed');
    }

    static get adapter() {
      return adapter(this);
    }

    get adapter() {
      return adapter(this);
    }

    static get IN_PAYLOAD() { return IN_PAYLOAD; }

    static async find(value, { ignoreExpiration = false } = {}) {
      let rethrow;
      try {
        assert.deepEqual(typeof value, 'string');
        const jti = this.getTokenId(value);
        assert(jti);
        const stored = await this.adapter.find(jti).catch((err) => {
          rethrow = true;
          throw err;
        });
        assert(stored);
        const payload = await this.verify(value, stored, { ignoreExpiration });
        assert.deepEqual(jti, payload.jti);

        return new this(payload);
      } catch (err) {
        if (rethrow) throw err;
        return undefined;
      }
    }

    emit(eventName) {
      provider.emit(`${snakeCase(this.kind)}.${eventName}`, this);
    }
  }

  class BaseModel extends hasFormat(provider, 'default', Class) {}

  return BaseModel;
};
