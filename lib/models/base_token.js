const IN_PAYLOAD = [
  'clientId',
  'jti',
  'kind',
  'format',
];

const assert = require('assert');

const epochTime = require('../helpers/epoch_time');
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
      Object.assign(this, payload);

      assert(!kind || kind === this.constructor.name, 'kind mismatch');

      this.kind = kind || this.constructor.name;
      this.jti = jti;
    }

    set client(client) {
      this.clientId = client.clientId;
      instance(this).client = client;
    }

    static expiresIn(...args) {
      const ttl = instance(provider).configuration(`ttl.${this.name}`);

      if (typeof ttl === 'number') {
        return ttl;
      }

      if (typeof ttl === 'function') {
        return ttl(...args);
      }

      return undefined;
    }

    get isValid() { return !this.isExpired; }

    get isExpired() { return this.exp <= epochTime(); }

    get remainingTTL() {
      if (!this.exp) {
        return this.expiration;
      }
      return this.exp - epochTime();
    }

    async save() {
      if (!this.jti) {
        this.jti = this.generateTokenId();
      }
      const [token, upsert] = await this.getValueAndPayload();

      if (this.constructor.format === 'legacy') {
        if (this.constructor.IN_PAYLOAD.includes('grantId') && !upsert.grantId) upsert.grantId = this.grantId;
        if (this.constructor.IN_PAYLOAD.includes('consumed') && !upsert.consumed) upsert.consumed = this.consumed;
        if (this.constructor.IN_PAYLOAD.includes('userCode') && !upsert.userCode) upsert.userCode = this.userCode;
      }
      await this.adapter.upsert(this.jti, upsert, this.remainingTTL);
      provider.emit('token.issued', this);

      return token;
    }

    destroy() {
      provider.emit('token.revoked', this);
      if (this.grantId) provider.emit('grant.revoked', this.grantId);

      return this.adapter.destroy(this.jti);
    }

    static get adapter() {
      return adapter(this);
    }

    get adapter() {
      return adapter(this);
    }

    static get IN_PAYLOAD() { return IN_PAYLOAD; }

    static async find(token = '', { ignoreExpiration = false } = {}) {
      let rethrow;
      try {
        const jti = this.getTokenId(token);
        assert(jti);
        const stored = await this.adapter.find(jti).catch((err) => {
          rethrow = true;
          throw err;
        });
        assert(stored);
        const payload = await this.verify(token, stored, { ignoreExpiration });
        assert.deepEqual(jti, payload.jti);
        const inst = new this({
          ...payload,
          ...(this.format === 'legacy' && stored.consumed ? { consumed: stored.consumed } : undefined),
        });

        return inst;
      } catch (err) {
        if (rethrow) throw err;
        return undefined;
      }
    }

    /**
     * @name expiration
     * @api public
     *
     * Return a Number (value of seconds) for this tokens TTL. Always return this.expiresIn when
     * set, otherwise return the desired TTL in seconds.
     *
     */
    get expiration() {
      if (!this.expiresIn) {
        this.expiresIn = this.constructor.expiresIn(this, instance(this).client);
      }

      return this.expiresIn;
    }
  }

  /**
   * @name generateTokenId
   * @api public
   *
   * Return a randomly generated Token instance ID (string)
   *
   * BaseToken.prototype.generateTokenId
   *   see implementations for each format in lib/models/formats
   */

  /**
   * @name getValueAndPayload
   * @api public
   *
   * Return an Array instance with the first member being a string representation of the token as
   * it should be returned to the client. Second member being an Object that should be passed to
   * the adapter for storage.
   *
   * BaseToken.prototype.getValueAndPayload
   *   see implementations for each format in lib/models/formats
   */

  /**
   * @name getTokenId
   * @static
   * @api public
   *
   * Return the Token instance ID related to the presented token value. This ID will be passed to
   * the adapter for lookup.
   *
   * @param token - the presented token string value
   *
   * BaseToken.prototype.constructor.getTokenId
   *   see implementations for each format in lib/models/formats
   */

  /**
   * @name verify
   * @static
   * @api public
   *
   * A verify function that asserts that the presented token is valid, not expired,
   * or otherwise manipulated with.
   *
   * @param token - the presented token string value
   * @param stored - data returned from the adapter token lookup
   * @param options - options object
   * @param options.ignoreExpiration - Boolean indicating whether expired but still stored
   *   tokens should pass this verification.
   *
   * BaseToken.prototype.constructor.verify
   *   see implementations for each format in lib/models/formats
   */

  class BaseToken extends hasFormat(provider, 'default', Class) {}

  return BaseToken;
};
