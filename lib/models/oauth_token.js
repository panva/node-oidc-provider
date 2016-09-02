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
const IS_MANDATORY = ['iat', 'iss', 'jti', 'kind'];

const _ = require('lodash');
const constantEquals = require('buffer-equals-constant');
const base64url = require('base64url');
const assert = require('assert');
const uuid = require('uuid');

const errors = require('../helpers/errors');
const JWT = require('../helpers/jwt');

module.exports = function getOAuthToken(provider) {
  return class OAuthToken {

    constructor(payload) {
      Object.assign(this, payload);

      this.jti = this.jti || uuid.v4();

      this.kind = this.kind || this.constructor.name;
      assert.equal(this.kind, this.constructor.name, 'kind mismatch');
    }

    static get adapter() {
      const Adapter = provider.configuration('adapter');
      if (!this._adapter) {
        this._adapter = new Adapter(this.name);
      }
      return this._adapter;
    }

    get adapter() {
      return this.constructor.adapter;
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

        return this.adapter.upsert(this.jti, upsert, expiresIn)
          .then(() => `${parts[1]}.${parts[2]}`);
      }).then((tokenValue) => {
        provider.emit('token.issued', this);
        return tokenValue;
      });
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

    static fromJWT(jwt, options) {
      const opts = options || /* istanbul ignore next */ {};
      opts.ignoreExpiration =
        'ignoreExpiration' in opts ? opts.ignoreExpiration : false;
      opts.issuer = provider.issuer;

      return JWT.verify(jwt, provider.keystore, opts)
        .then(result => new this(Object.assign(result.payload, result.header)));
    }

    static decode(wildToken) {
      try {
        const parts = wildToken.split('.');
        assert.ok(parts.length === 2, 'token should consist of two parts');

        const decoded = JSON.parse(base64url.decode(parts[0]));

        IS_MANDATORY.forEach((prop) => {
          assert.ok(decoded[prop] !== undefined, `token missing payload property (${prop})`);
          assert.ok(decoded[prop], `token payload property invalid (${decoded[prop]})`);
        });

        return {
          decoded,
          payload: parts[0],
          signature: parts[1],
        };
      } catch (err) {
        throw new errors.InvalidTokenError();
      }
    }

    static find(tokenValue, options) {
      const opts = options || /* istanbul ignore next */ {};
      opts.ignoreExpiration = 'ignoreExpiration' in opts ? opts.ignoreExpiration : false;

      let provided;

      try {
        provided = this.decode(tokenValue);
      } catch (err) {
        return Promise.reject(new errors.InvalidTokenError());
      }

      return this.adapter.find(provided.decoded.jti).then((token) => {
        if (token) {
          const jwt = [token.header, provided.payload, provided.signature].join('.');

          const expected = [
            token.header, token.payload, token.signature,
          ].join('.');

          /* istanbul ignore if */
          if (!constantEquals(new Buffer(jwt), new Buffer(expected))) {
            throw new errors.InvalidTokenError();
          }

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
