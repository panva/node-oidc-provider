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
  'kind',
  'nonce',
  'redirectUri',
  'scope',
  'sid',
];

const { promisify } = require('util');
const { pick } = require('lodash');
const constantEquals = require('buffer-equals-constant');
const assert = require('assert');
const base64url = require('base64url');
const uuid = require('uuid');

const epochTime = require('../helpers/epoch_time');
const instance = require('../helpers/weak_cache');
const JWT = require('../helpers/jwt');
const randomBytes = promisify(require('crypto').randomBytes);

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

    get expiration() { return this.expiresIn || this.constructor.expiresIn; }
    static get expiresIn() { return instance(provider).configuration(`ttl.${this.name}`); }
    get isValid() { return !this.consumed && !this.isExpired; }
    get isExpired() { return this.exp <= epochTime(); }

    async save() {
      const [token, upsert] = await this.getValueAndPayload();

      if (this.grantId) upsert.grantId = this.grantId;
      await this.adapter.upsert(this.jti, upsert, this.expiresIn);
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
      try {
        const jti = this.getJtiFromToken(token);
        assert(jti);
        const stored = await this.adapter.find(jti);
        assert(stored);
        const payload = await this.verify(token, stored, { ignoreExpiration });
        const inst = new this(Object.assign(payload));
        if (stored.consumed !== undefined) inst.consumed = stored.consumed;

        return inst;
      } catch (err) {
        return undefined;
      }
    }

    /**
     * @name getValueAndPayload
     * @api public
     */
    async getValueAndPayload() {
      const [jwt, random] = await Promise.all([
        JWT.sign(pick(this, this.constructor.IN_PAYLOAD), undefined, 'none', {
          expiresIn: this.expiration,
          issuer: provider.issuer,
        }),
        randomBytes(64),
      ]);

      const [header, payload,, signature] = [...jwt.split('.'), base64url(random)];
      return [`${this.jti}${signature}`, {
        header,
        payload,
        signature,
      }];
    }

    /**
     * @name getJtiFromToken
     * @api public
     */
    static getJtiFromToken(token) {
      return token.substring(0, 48);
    }

    /**
     * @name verify
     * @api public
     */
    static async verify(token, stored, { ignoreExpiration }) {
      assert(constantEquals(Buffer.from(token.substring(48)), Buffer.from(stored.signature)));
      const { payload } = JWT.decode([stored.header, stored.payload, stored.signature].join('.'));
      JWT.assertPayload(payload, { ignoreExpiration, issuer: provider.issuer });
      return payload;
    }
  };
};
