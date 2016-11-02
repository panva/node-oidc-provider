'use strict';

const _ = require('lodash');
const tokenHash = require('oidc-token-hash');

const getMask = require('../helpers/claims');
const epochTime = require('../helpers/epoch_time');
const JWT = require('../helpers/jwt');
const errors = require('../helpers/errors');
const instance = require('../helpers/weak_cache');

const hashes = ['at_hash', 'c_hash', 'rt_hash'];

module.exports = function getIdToken(provider) {
  const Claims = getMask(instance(provider).configuration());

  return class IdToken {
    constructor(available, sector) {
      this.extra = {};
      this.available = available;
      this.sector = sector;
    }

    static get expiresIn() { return instance(provider).configuration(`ttl.${this.name}`); }

    set(key, value) { this.extra[key] = value; }

    payload() {
      const mask = new Claims(this.available, this.sector);

      mask.scope(this.scope);
      mask.mask(this.mask);

      return _.merge(mask.result(), this.extra);
    }

    sign(client, options) {
      const opts = options || /* istanbul ignore next */ {};
      opts.use = 'use' in opts ? opts.use : 'idtoken';
      opts.expiresAt = 'expiresAt' in opts ? opts.expiresAt : null;
      opts.noExp = 'noExp' in opts ? opts.noExp : null;

      const expiresIn = (() => {
        if (opts.expiresAt) return opts.expiresAt - epochTime();
        return undefined;
      })();

      const alg = opts.use === 'userinfo' ?
        client.userinfoSignedResponseAlg : client.idTokenSignedResponseAlg;

      const payload = this.payload();

      const promise = (() => {
        if (alg) {
          const keystore = alg && alg.startsWith('HS') ? client.keystore : instance(provider).keystore;
          const key = keystore && keystore.get({ alg });

          hashes.forEach((claim) => {
            if (payload[claim]) payload[claim] = tokenHash.generate(payload[claim], alg);
          });

          return JWT.sign(payload, key, alg, {
            audience: client.clientId,
            expiresIn: opts.noExp ? undefined : (expiresIn || this.constructor.expiresIn),
            issuer: provider.issuer,
            subject: payload.sub,
          });
        }

        return Promise.resolve(JSON.stringify(payload));
      })();

      const encryption = opts.use === 'userinfo' ? {
        alg: client.userinfoEncryptedResponseAlg,
        enc: client.userinfoEncryptedResponseEnc,
      } : {
        alg: client.idTokenEncryptedResponseAlg,
        enc: client.idTokenEncryptedResponseEnc,
      };

      if (encryption.enc) {
        return promise.then((signed) => {
          if (client.keystore.stale()) return client.keystore.refresh().then(() => signed);
          return signed;
        })
        .then((signed) => {
          const encryptionKey = client.keystore.get({ alg: encryption.alg });
          if (!encryptionKey) {
            throw new errors.InvalidClientMetadata(
              `no suitable encryption key found (${encryption.alg})`);
          }
          return JWT.encrypt(signed, encryptionKey, encryption.enc, encryption.alg);
        });
      }

      return promise;
    }

    static validate(jwt, client) {
      const alg = client.idTokenSignedResponseAlg;
      const options = { ignoreExpiration: true, issuer: provider.issuer };

      const keyOrStore = (() => {
        if (/^(ES|RS)\d{3}/.exec(alg)) {
          return instance(provider).keystore;
        } else if (alg.startsWith('HS')) {
          return client.keystore;
        }
        return undefined;
      })();

      if (keyOrStore !== undefined) return JWT.verify(jwt, keyOrStore, options);

      const decode = JWT.decode(jwt);
      try {
        JWT.assertPayload(decode.payload, options);
      } catch (err) {
        return Promise.reject(err);
      }
      return Promise.resolve(decode);
    }
  };
};
