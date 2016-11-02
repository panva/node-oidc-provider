'use strict';

const IN_PAYLOAD = [
  'accountId',
  'acr',
  'authTime',
  'claims',
  'clientId',
  'codeChallenge',
  'codeChallengeMethod',
  'grantId',
  'jti',
  'kind',
  'nonce',
  'redirectUri',
  'scope',
  'sid',
];

const _ = require('lodash');
const constantEquals = require('buffer-equals-constant');
const assert = require('assert');
const base64url = require('base64url');
const uuid = require('uuid');

const errors = require('../helpers/errors');
const epochTime = require('../helpers/epoch_time');
const instance = require('../helpers/weak_cache');
const JWT = require('../helpers/jwt');

const adapterCache = new WeakMap();

module.exports = function getBaseToken(provider) {
  function adapter(ctx) {
    const obj = typeof ctx === 'function' ? ctx : ctx.constructor;

    if (!adapterCache.has(obj)) {
      adapterCache.set(obj, new (instance(provider).configuration('adapter'))(obj.name));
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

    save() {
      const key = instance(provider).integrity.get();
      const alg = key.alg;

      const expiresIn = this.expiresIn || this.constructor.expiresIn;

      return JWT.sign(_.pick(this, IN_PAYLOAD), key, alg, {
        expiresIn,
        issuer: provider.issuer,
      }).then((jwt) => {
        const parts = jwt.split('.');

        const upsert = {
          header: parts[0],
          payload: parts[1],
          signature: parts[2],
        };

        if (this.grantId) upsert.grantId = this.grantId;

        return adapter(this).upsert(this.jti, upsert, expiresIn)
          .then(() => `${this.jti}${upsert.signature}`);
      }).then((tokenValue) => {
        provider.emit('token.issued', this);
        return tokenValue;
      });
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

    static fromJWT(jwt, options) {
      const opts = options || /* istanbul ignore next */ {};
      opts.ignoreExpiration = 'ignoreExpiration' in opts ? opts.ignoreExpiration : false;
      opts.issuer = provider.issuer;

      const keystore = instance(provider).integrity;
      return JWT.verify(jwt, keystore, opts)
        .then(result => new this(Object.assign(result.payload)));
    }

    static find(tokenValue, options) {
      const opts = options || /* istanbul ignore next */ {};
      opts.ignoreExpiration = 'ignoreExpiration' in opts ? opts.ignoreExpiration : false;

      let jti;
      let sig;

      try {
        jti = tokenValue.substring(0, 48);
        sig = tokenValue.substring(48);
        assert(jti);
        assert(sig);
      } catch (err) {
        return Promise.reject(new errors.InvalidTokenError());
      }

      return adapter(this).find(jti).then((token) => {
        if (token) {
          /* istanbul ignore if */
          if (!constantEquals(new Buffer(sig), new Buffer(token.signature))) {
            throw new errors.InvalidTokenError();
          }

          const jwt = [token.header, token.payload, token.signature].join('.');
          return this.fromJWT(jwt, opts).then((validated) => {
            const result = validated;
            if (token.consumed !== undefined) result.consumed = token.consumed;

            return result;
          }).catch(() => {
            throw new errors.InvalidTokenError();
          });
        }

        return undefined;
      });
    }
  };
};
