'use strict';

const IN_PAYLOAD = ['kind', 'jti', 'nonce'];
const IN_HEADER = [
  'accountId',
  'clientId',
  'authTime',
  'redirectUri',
  'claims',
  'grantId',
  'acr',
  'scope',
  'sid',
];

const _ = require('lodash');
const constantEquals = require('buffer-equals-constant');
const assert = require('assert');
const base64url = require('base64url');
const uuid = require('uuid');

const errors = require('../helpers/errors');
const instance = require('../helpers/weak_cache');
const JWT = require('../helpers/jwt');

module.exports = function getOAuthToken(provider) {
  function adapter(ctx) {
    const name = typeof ctx === 'function' ? ctx.name : ctx.constructor.name;

    if (!instance(provider)[name]) {
      instance(provider)[name] = new (provider.configuration('adapter'))(name);
    }

    return instance(provider)[name];
  }

  return class OAuthToken {

    constructor(payload) {
      Object.assign(this, payload);

      this.jti = this.jti || base64url.encode(uuid.v4());

      this.kind = this.kind || this.constructor.name;
      assert.equal(this.kind, this.constructor.name, 'kind mismatch');
    }

    static get expiresIn() {
      return provider.configuration(`ttl.${this.name}`);
    }

    get standardPayload() {
      return IN_PAYLOAD;
    }

    get headerPayload() {
      return IN_HEADER;
    }

    get isValid() {
      return !this.consumed && !this.isExpired;
    }

    get isExpired() {
      return this.exp <= Date.now() / 1000 | 0;
    }

    save() {
      const key = provider.keystore.get({
        alg: 'RS256',
        use: 'sig',
      });

      const expiresIn = this.expiresIn || this.constructor.expiresIn;

      return JWT.sign(_.pick(this, this.standardPayload), key, 'RS256', {
        expiresIn,
        headers: _.pick(this, this.headerPayload),
        issuer: provider.issuer,
      }).then((jwt) => {
        const parts = jwt.split('.');

        const upsert = {
          header: parts[0],
          payload: parts[1],
          signature: parts[2],
        };

        if (this.grantId) {
          upsert.grantId = this.grantId;
        }

        return adapter(this).upsert(this.jti, upsert, expiresIn)
          .then(() => `${this.jti}${parts[2]}`);
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
      opts.ignoreExpiration =
        'ignoreExpiration' in opts ? opts.ignoreExpiration : false;
      opts.issuer = provider.issuer;

      return JWT.verify(jwt, provider.keystore, opts)
        .then(result => new this(Object.assign(result.payload, result.header)));
    }

    static find(tokenValue, options) {
      const opts = options || /* istanbul ignore next */ {};
      opts.ignoreExpiration = 'ignoreExpiration' in opts ? opts.ignoreExpiration : false;

      let jti;
      let sig;

      try {
        jti = tokenValue.substring(0, 48);
        sig = tokenValue.substring(48);
        assert.ok(jti);
        assert.ok(sig);
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
            if (token.consumed !== undefined) {
              result.consumed = token.consumed;
            }

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
