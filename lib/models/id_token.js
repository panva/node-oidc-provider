'use strict';

const _ = require('lodash');

const tokenHash = require('../helpers/token_hash');
const getMask = require('../helpers/claims');
const JWT = require('../helpers/jwt');

const hashes = ['at_hash', 'c_hash', 'rt_hash'];

module.exports = function getIdToken(provider) {
  const Claims = getMask(provider.configuration);

  return class IdToken {
    constructor(available, sector) {
      this.extra = {};
      this.available = available;
      this.sector = sector;
    }

    static get expiresIn() {
      /* istanbul ignore if */
      if (!this.ttl) {
        throw new Error('expiresIn not set');
      }
      return this.ttl;
    }

    static set expiresIn(ttl) {
      this.ttl = ttl;
    }

    set(key, value) {
      this.extra[key] = value;
    }

    payload() {
      const mask = new Claims(this.available, this.sector);

      mask.scope(this.scope);
      mask.mask(this.mask);

      return _.merge(mask.result(), this.extra);
    }

    toJWT(client, options) {
      const opts = options || {};
      opts.use = 'use' in opts ? opts.use : 'idtoken';
      opts.expiresAt = 'expiresAt' in opts ? opts.expiresAt : null;

      let expiresIn;

      if (opts.expiresAt) {
        expiresIn = opts.expiresAt - Date.now() / 1000 | 0;
      }

      const alg = opts.use === 'userinfo' ?
        client.userinfoSignedResponseAlg : client.idTokenSignedResponseAlg;

      const keystore = alg.startsWith('HS') ? client.keystore : provider.keystore;

      const key = keystore.get({ alg });

      const flags = {
        audience: client.clientId,
        expiresIn: expiresIn || this.constructor.expiresIn,
        issuer: provider.issuer,
      };

      const payload = this.payload();

      hashes.forEach((claim) => {
        if (payload[claim]) {
          payload[claim] = tokenHash(payload[claim], alg);
        }
      });

      const promise = JWT.sign(payload, key, alg, flags);

      const encryption = opts.use === 'userinfo' ? {
        alg: client.userinfoEncryptedResponseAlg,
        enc: client.userinfoEncryptedResponseEnc,
      } : {
        alg: client.idTokenEncryptedResponseAlg,
        enc: client.idTokenEncryptedResponseEnc,
      };

      if (encryption.enc) {
        return promise.then((signed) => client.keystore.refresh().then(() => signed))
          .then((signed) => {
            const use = client.keystore.get({
              alg: encryption.alg,
              enc: encryption.enc,
            });
            return JWT.encrypt(signed, use, encryption.enc, encryption.alg);
          });
      }

      return promise;
    }

    static validate(jwt, client) {
      const alg = client.idTokenSignedResponseAlg;
      let keyOrStore;

      const options = {
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
