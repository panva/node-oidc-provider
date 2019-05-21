const epochTime = require('../helpers/epoch_time');
const instance = require('../helpers/weak_cache');

const ctxRef = require('./ctx_ref');

module.exports = function getBaseToken(provider) {
  class BaseToken extends instance(provider).BaseModel {
    constructor({ client, expiresIn, ...rest } = {}) {
      super(rest);
      if (typeof client !== 'undefined') {
        this.client = client;
      }
      if (typeof expiresIn !== 'undefined') {
        this.expiresIn = expiresIn;
      }
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
      return super.save(this.remainingTTL);
    }

    static get IN_PAYLOAD() {
      return [
        ...super.IN_PAYLOAD,
        'clientId',
        'format',
      ];
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
        this.expiresIn = this.constructor.expiresIn(ctxRef.get(this), this, instance(this).client);
      }

      return this.expiresIn;
    }

    get scopes() {
      return new Set(this.scope && this.scope.split(' '));
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

  // class BaseToken extends hasFormat(provider, 'default', Class) {}

  return BaseToken;
};
