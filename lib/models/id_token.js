const { strict: assert } = require('assert');
const { format } = require('util');

const merge = require('lodash/merge');
const { generate: tokenHash } = require('oidc-token-hash');

const epochTime = require('../helpers/epoch_time');
const JWT = require('../helpers/jwt');
const { InvalidClientMetadata } = require('../helpers/errors');
const instance = require('../helpers/weak_cache');

const hashes = ['at_hash', 'c_hash', 's_hash'];

const messages = {
  sig: {
    idtoken: 'client secret is expired - cannot issue an ID Token (%s)',
    logout: 'client secret is expired - cannot issue a Logout Token (%s)',
    userinfo: 'client secret is expired - cannot respond with %s JWT UserInfo response',
    introspection: 'client secret is expired - cannot respond with %s JWT Introspection response',
  },
  enc: {
    idtoken: 'client secret is expired - cannot issue an encrypted ID Token (%s)',
    logout: 'client secret is expired - cannot issue an encrypted Logout Token (%s)',
    userinfo: 'client secret is expired - cannot respond with %s encrypted JWT UserInfo response',
    introspection: 'client secret is expired - cannot respond with %s encrypted JWT Introspection response',
  },
};

module.exports = function getIdToken(provider) {
  return class IdToken {
    constructor(available, { ctx, client = ctx ? ctx.oidc.client : undefined }) {
      assert.equal(
        typeof available, 'object',
        'expected claims to be an object, are you sure claims() method resolves with or returns one?',
      );
      this.extra = {};
      this.available = available;
      this.client = client;
      this.ctx = ctx;
    }

    static expiresIn(...args) {
      const ttl = instance(provider).configuration(`ttl.${this.name}`);

      if (typeof ttl === 'number') {
        return ttl;
      }

      return ttl(...args);
    }

    set(key, value) { this.extra[key] = value; }

    async payload() {
      const mask = new provider.Claims(this.available, { ctx: this.ctx, client: this.client });

      mask.scope(this.scope);
      mask.mask(this.mask);
      mask.rejected(this.rejected);

      return merge(await mask.result(), this.extra);
    }

    // TODO: in v7.x remove the use default
    async issue({ use = 'idtoken', expiresAt = null } = {}) {
      const { client } = this;
      const expiresIn = expiresAt ? expiresAt - epochTime() : undefined;
      let alg;

      const payload = await this.payload();
      let signOptions;
      let encryption;

      switch (use) {
        case 'idtoken':
          alg = client.idTokenSignedResponseAlg;
          signOptions = {
            audience: client.clientId,
            expiresIn: (expiresIn || this.constructor.expiresIn(this.ctx, this, client)),
            issuer: provider.issuer,
            subject: payload.sub,
          };
          encryption = {
            alg: client.idTokenEncryptedResponseAlg,
            enc: client.idTokenEncryptedResponseEnc,
          };
          break;
        case 'logout':
          alg = client.idTokenSignedResponseAlg;
          signOptions = {
            audience: client.clientId,
            issuer: provider.issuer,
            subject: payload.sub,
          };
          encryption = {
            alg: client.idTokenEncryptedResponseAlg,
            enc: client.idTokenEncryptedResponseEnc,
          };
          break;
        case 'userinfo':
          alg = client.userinfoSignedResponseAlg;
          signOptions = {
            audience: client.clientId,
            issuer: provider.issuer,
            subject: payload.sub,
            expiresIn,
          };
          encryption = {
            alg: client.userinfoEncryptedResponseAlg,
            enc: client.userinfoEncryptedResponseEnc,
          };
          break;
        case 'introspection':
          alg = client.introspectionSignedResponseAlg;
          signOptions = {
            noIat: true,
          };
          encryption = {
            alg: client.introspectionEncryptedResponseAlg,
            enc: client.introspectionEncryptedResponseEnc,
          };
          break;
        case 'authorization':
          alg = client.authorizationSignedResponseAlg;
          signOptions = {
            audience: client.clientId,
            expiresIn: 60,
            issuer: provider.issuer,
            noIat: true,
          };
          encryption = {
            alg: client.authorizationEncryptedResponseAlg,
            enc: client.authorizationEncryptedResponseEnc,
          };
          break;
        /* istanbul ignore next */
        default:
          throw new TypeError('invalid use option');
      }

      hashes.forEach((claim) => {
        if (payload[claim]) {
          payload[claim] = tokenHash(payload[claim], alg);
        }
      });

      const signed = await (() => {
        if (!alg) {
          return JSON.stringify(payload);
        }

        let keystore;
        if (alg && alg.startsWith('HS')) {
          if (use !== 'authorization') { // handled in checkResponseMode
            client.checkClientSecretExpiration(format(messages.sig[use], alg));
          }
          ({ keystore } = client);
        } else {
          ({ keystore } = instance(provider));
        }

        const key = keystore && keystore.get({ alg, use: 'sig' });

        return JWT.sign(payload, key, alg, signOptions);
      })();

      if (!encryption.enc) {
        return signed;
      }

      await client.keystore.refresh();

      if (/^(A|P|dir$)/.test(encryption.alg)) {
        if (use !== 'authorization') { // handled in checkResponseMode
          client.checkClientSecretExpiration(format(messages.enc[use], encryption.alg));
        }
      }

      let encryptionKey;
      if (encryption.alg === 'dir') {
        encryptionKey = client.keystore.get({ alg: encryption.enc, use: 'enc' });
      } else {
        encryptionKey = client.keystore.get({ alg: encryption.alg, use: 'enc' });
      }

      if (!encryptionKey) {
        throw new InvalidClientMetadata(`no suitable encryption key found (${encryption.alg})`);
      }

      return JWT.encrypt(signed, encryptionKey, {
        enc: encryption.enc,
        alg: encryption.alg,
        cty: alg ? undefined : 'json', // if there's no signing alg the cty is json, else jwt
      });
    }

    static async validate(jwt, client) {
      const alg = client.idTokenSignedResponseAlg;

      let keyOrStore;
      if (alg.startsWith('HS')) {
        client.checkClientSecretExpiration('client secret is expired - cannot validate ID Token Hint');
        keyOrStore = client.keystore;
      } else if (alg !== 'none') {
        keyOrStore = instance(provider).keystore;
      }

      const opts = {
        ignoreExpiration: true,
        audience: client.clientId,
        issuer: provider.issuer,
        clockTolerance: instance(provider).configuration('clockTolerance'),
        algorithm: alg,
      };

      if (keyOrStore === undefined) {
        const decoded = JWT.decode(jwt);
        JWT.assertHeader(decoded.header, opts);
        JWT.assertPayload(decoded.payload, opts);
        return decoded;
      }

      return JWT.verify(jwt, keyOrStore, opts);
    }
  };
};
