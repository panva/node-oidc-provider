const IN_PAYLOAD = [
  'accountId',
  'acr',
  'amr',
  'authTime',
  'claims',
  'clientId',
  'codeChallenge', // for authorization code
  'codeChallengeMethod', // for authorization code
  'grantId',
  'jti',
  'aud',
  'kind',
  'nonce',
  'redirectUri',
  'scope',
  'sid',
];

const { pick } = require('lodash');
const constantEquals = require('../helpers/constant_equals');
const assert = require('assert');
const base64url = require('base64url');
const uuid = require('uuid/v4');
const { randomBytes } = require('crypto');

const epochTime = require('../helpers/epoch_time');
const instance = require('../helpers/weak_cache');
const JWT = require('../helpers/jwt');

const adapterCache = new WeakMap();

module.exports = function getBaseToken(provider) {
  function adapter(ctx) {
    const obj = typeof ctx === 'function' ? ctx : ctx.constructor;

    if (!adapterCache.has(obj)) {
      adapterCache.set(obj, new (instance(provider).Adapter)(obj.name));
    }

    return adapterCache.get(obj);
  }

  return class BaseToken {
    constructor(payload) {
      Object.assign(this, payload);

      this.jti = this.jti || base64url.encode(uuid());

      this.kind = this.kind || this.constructor.name;
      assert.equal(this.kind, this.constructor.name, 'kind mismatch');
    }

    static get expiresIn() { return instance(provider).configuration(`ttl.${this.name}`); }
    get isValid() { return !this.consumed && !this.isExpired; }
    get isExpired() { return this.exp <= epochTime(); }

    async save() {
      const [token, upsert] = await this.getValueAndPayload();

      if (this.grantId) upsert.grantId = this.grantId;
      await this.adapter.upsert(this.jti, upsert, this.expiration);
      provider.emit('token.issued', this);

      return token;
    }

    destroy() {
      provider.emit('token.revoked', this);
      if (this.grantId) provider.emit('grant.revoked', this.grantId);

      return this.adapter.destroy(this.jti);
    }

    consume() {
      provider.emit('token.consumed', this);
      return this.adapter.consume(this.jti);
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
        const inst = new this(Object.assign(payload));
        if (stored.consumed !== undefined) inst.consumed = stored.consumed;

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
      return this.expiresIn || this.constructor.expiresIn;
    }

    /**
     * @name getValueAndPayload
     * @api public
     *
     * Return an Array instance with the first member being a string representation of the token as
     * it should be returned to the client. Second member being an Object that should be passed to
     * the adapter for storage.
     *
     */
    async getValueAndPayload() {
      const jwt = await JWT.sign(pick(this, this.constructor.IN_PAYLOAD), undefined, 'none', {
        expiresIn: this.expiration,
        issuer: provider.issuer,
      });

      const [header, payload] = jwt.split('.');
      const signature = base64url.encode(randomBytes(64));

      return [`${this.jti}${signature}`, {
        header,
        payload,
        signature,
      }];
    }

    /**
     * @name getTokenId
     * @api public
     *
     * Return the Token instance ID related of the presented token. This ID will be passed to the
     * adapter for lookup.
     *
     * @param token - the presented token string value
     *
     */
    static getTokenId(token) {
      return token.substring(0, 48);
    }

    /**
     * @name verify
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
     */
    static async verify(token, stored, options) {
      assert(constantEquals(token.substring(48), stored.signature, 1000));
      const { payload } = JWT.decode([stored.header, stored.payload, stored.signature].join('.'));
      JWT.assertPayload(payload, {
        ignoreExpiration: options.ignoreExpiration,
        issuer: provider.issuer,
        clockTolerance: instance(provider).configuration('clockTolerance'),
      });
      return payload;
    }
  };
};
