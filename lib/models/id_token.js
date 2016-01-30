'use strict';

let _ = require('lodash');
let assert = require('assert');

let tokenHash = require('../helpers/token_hash');
let JWT = require('../helpers/jwt');

let hashed = ['at_hash', 'c_hash', 'rt_hash'];

module.exports = function(provider) {

  let ClaimsMask = require('../helpers/claims_mask')(provider.configuration);

  return class IdToken {
    constructor(available, sector) {
      this.available = available;
      this.sector = sector;
    }

    static get expiresIn() {
      if (!this.ttl) {
        throw 'expiresIn not set';
      }
      return this.ttl;
    }

    static set expiresIn(ttl) {
      this.ttl = ttl;
    }

    set extra(extra) { // jshint ignore:line
      assert(_.isPlainObject(extra), 'extra need to be a plain object');
      this._extras = _.merge(this._extras || {}, extra);
    }

    set extras(extras) {
      assert(_.isPlainObject(extras), 'extras need to be a plain object');
      this._extras = extras;
    }

    get extras() {
      return this._extras;
    }

    payload() {
      let mask = new ClaimsMask(this.available, this.sector);

      mask.scope = this.scope;
      mask.mask = this.mask;

      return _.merge(mask.result(), this.extras);
    }

    toJWT(client, opts) {
      opts = opts || {};
      opts.use = 'use' in opts ? opts.use : 'idtoken';
      opts.expiresAt = 'expiresAt' in opts ? opts.expiresAt : null;

      let expiresIn;

      if (opts.expiresAt) {
        expiresIn = opts.expiresAt - Date.now() / 1000 | 0;
      }

      let alg = opts.use === 'userinfo' ?
        client.userinfoSignedResponseAlg : client.idTokenSignedResponseAlg;

      let keystore = alg.startsWith('HS') ? client.keystore : provider.keystore;

      let key = keystore.get({
        alg: alg,
      });

      let options = {
        audience: client.clientId,
        expiresIn: expiresIn || this.constructor.expiresIn,
        issuer: provider.issuer,
      };

      let payload = this.payload();

      hashed.forEach(claim => {
        if (payload[claim]) {
          payload[claim] = tokenHash(payload[claim], alg);
        }
      });

      let promise = JWT.sign(payload, key, alg, options);

      let encryption = opts.use === 'userinfo' ? {
        alg: client.userinfoEncryptedResponseAlg,
        enc: client.userinfoEncryptedResponseEnc,
      } : {
        alg: client.idTokenEncryptedResponseAlg,
        enc: client.idTokenEncryptedResponseEnc,
      };

      if (encryption.enc) {
        return promise.then((signed) => {
          return client.keystore.refresh().then(() => {
            return signed;
          });
        }).then((signed) => {
          let key = client.keystore.get({
            alg: encryption.alg,
            enc: encryption.enc,
          });
          return JWT.encrypt(signed, key, encryption.enc, encryption.alg);
        });
      }

      return promise;

    }

    static validate(jwt, client) {
      let alg = client.idTokenSignedResponseAlg,
        keyOrStore;

      let options = {
        ignoreExpiration: true,
        issuer: provider.issuer,
      };

      if (/^(ES|RS)\d{3}/.exec(alg)) {
        keyOrStore = provider.keystore;
      } else if (alg.startsWith('HS')) {
        keyOrStore = client.keystore.get('clientSecret');
      }

      if (!_.isUndefined(keyOrStore)) {
        return JWT.verify(jwt, keyOrStore, options);
      }

      return Promise.resolve(JWT.decode(jwt));
    }
  };
};
