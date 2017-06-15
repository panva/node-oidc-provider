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

const { InvalidTokenError } = require('../helpers/errors');
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

    static get expiresIn() { return instance(provider).configuration(`ttl.${this.name}`); }
    get isValid() { return !this.consumed && !this.isExpired; }
    get isExpired() { return this.exp <= epochTime(); }

    async save() {
      const expiresIn = this.expiresIn || this.constructor.expiresIn;

      const [jwt, signature] = await Promise.all([
        JWT.sign(pick(this, IN_PAYLOAD), undefined, 'none', {
          expiresIn,
          issuer: provider.issuer,
        }),
        randomBytes(64),
      ]);

      const parts = jwt.split('.');

      const upsert = {
        signature: base64url(signature),
        header: parts[0],
        payload: parts[1],
      };

      if (this.grantId) upsert.grantId = this.grantId;

      const tokenValue = adapter(this).upsert(this.jti, upsert, expiresIn)
        .then(() => `${this.jti}${upsert.signature}`);

      provider.emit('token.issued', this);
      return tokenValue;
    }

    destroy() {
      provider.emit('token.revoked', this);
      if (this.grantId) provider.emit('grant.revoked', this.grantId);

      return adapter(this).destroy(this.jti);
    }

    consume() {
      provider.emit('token.consumed', this);
      return adapter(this).consume(this.jti);
    }

    static fromJWT(jwt, { ignoreExpiration = false, issuer = provider.issuer } = {}) {
      const { payload } = JWT.decode(jwt);
      JWT.assertPayload(payload, { ignoreExpiration, issuer });
      return new this(Object.assign(payload));
    }

    static async find(tokenValue, { ignoreExpiration = false } = {}) {
      let jti;
      let sig;

      try {
        jti = tokenValue.substring(0, 48);
        sig = tokenValue.substring(48);
        assert(jti);
        assert(sig);
      } catch (err) {
        throw new InvalidTokenError();
      }

      const token = await adapter(this).find(jti);
      if (!token) return undefined;

      /* istanbul ignore if */
      if (!constantEquals(new Buffer(sig), new Buffer(token.signature))) {
        throw new InvalidTokenError();
      }

      const jwt = [token.header, token.payload, token.signature].join('.');
      try {
        const validated = this.fromJWT(jwt, { ignoreExpiration });
        if (token.consumed !== undefined) validated.consumed = token.consumed;
        return validated;
      } catch (err) {
        throw new InvalidTokenError();
      }
    }
  };
};
