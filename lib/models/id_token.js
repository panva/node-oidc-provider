const assert = require('assert');

const { merge } = require('lodash');
const { generate: tokenHash } = require('oidc-token-hash');

const epochTime = require('../helpers/epoch_time');
const JWT = require('../helpers/jwt');
const { InvalidClientMetadata } = require('../helpers/errors');
const instance = require('../helpers/weak_cache');
const ensureConform = require('../helpers/ensure_conform');

const hashes = ['at_hash', 'c_hash', 's_hash'];

module.exports = function getIdToken(provider) {
  return class IdToken {
    constructor(available, client) {
      assert.deepEqual(
        typeof available, 'object',
        'expected claims to be an object, are you sure claims() method resolves with or returns one?',
      );
      this.extra = {};
      this.available = available;
      this.client = client;
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
      const mask = new provider.Claims(this.available, this.client);

      mask.scope(this.scope);
      mask.mask(this.mask);
      mask.rejected(this.rejected);

      return merge(await mask.result(), this.extra);
    }

    async sign({
      use = 'idtoken',
      audiences = null,
      expiresAt = null,
      noExp = null,
    } = {}) {
      const { client } = this;
      const expiresIn = expiresAt ? expiresAt - epochTime() : undefined;
      let alg;

      switch (use) {
        case 'idtoken':
          alg = client.idTokenSignedResponseAlg;
          break;
        case 'userinfo':
          alg = client.userinfoSignedResponseAlg;
          break;
        case 'introspection':
          alg = client.introspectionSignedResponseAlg;
          break;
        case 'authorization':
          alg = client.authorizationSignedResponseAlg;
          break;
        /* istanbul ignore next */
        default:
          throw new Error('invalid IdToken use');
      }

      const payload = await this.payload();

      hashes.forEach((claim) => {
        if (payload[claim]) payload[claim] = tokenHash(payload[claim], alg);
      });

      const signed = await (() => {
        if (!alg) return JSON.stringify(payload);

        const keystore = alg && alg.startsWith('HS') ? client.keystore : instance(provider).keystore;
        const key = keystore && keystore.get({ alg, use: 'sig' });

        let signOptions;
        if (use === 'introspection') {
          signOptions = { noIat: true };
        } else if (use === 'authorization') {
          signOptions = {
            noIat: true, expiresIn: 60, audience: client.clientId, issuer: provider.issuer,
          };
        } else {
          signOptions = {
            authorizedParty: audiences ? client.clientId : undefined,
            audience: audiences ? ensureConform(audiences, client.clientId) : client.clientId,
            expiresIn: noExp ? undefined : (expiresIn || this.constructor.expiresIn(this, client)),
            issuer: provider.issuer,
            subject: payload.sub,
          };
        }

        return JWT.sign(payload, key, alg, signOptions);
      })();

      let encryption;
      switch (use) {
        case 'idtoken':
          encryption = {
            alg: client.idTokenEncryptedResponseAlg,
            enc: client.idTokenEncryptedResponseEnc,
          };
          break;
        case 'userinfo':
          encryption = {
            alg: client.userinfoEncryptedResponseAlg,
            enc: client.userinfoEncryptedResponseEnc,
          };
          break;
        case 'introspection':
          encryption = {
            alg: client.introspectionEncryptedResponseAlg,
            enc: client.introspectionEncryptedResponseEnc,
          };
          break;
        case 'authorization':
          encryption = {
            alg: client.authorizationEncryptedResponseAlg,
            enc: client.authorizationEncryptedResponseEnc,
          };
          break;
        /* istanbul ignore next */
        default:
          encryption = {};
      }

      if (!encryption.enc) return signed;
      await client.keystore.refresh();

      const encryptionKey = client.keystore.get({ alg: encryption.alg, use: 'enc' });
      if (!encryptionKey) {
        throw new InvalidClientMetadata(`no suitable encryption key found (${encryption.alg})`);
      }
      return JWT.encrypt(signed, encryptionKey, encryption.enc, encryption.alg, alg ? undefined : 'json');
    }

    static async validate(jwt, client) {
      const alg = client.idTokenSignedResponseAlg;
      const opts = {
        ignoreExpiration: true,
        audience: client.clientId,
        issuer: provider.issuer,
        clockTolerance: instance(provider).configuration('clockTolerance'),
      };

      let keyOrStore;
      if (/^(ES|RS)\d{3}/.test(alg)) {
        keyOrStore = instance(provider).keystore;
      } else if (alg.startsWith('HS')) {
        keyOrStore = client.keystore;
      }

      if (keyOrStore !== undefined) {
        return JWT.verify(jwt, keyOrStore, opts);
      }

      const decoded = JWT.decode(jwt);
      JWT.assertPayload(decoded.payload, opts);
      return decoded;
    }
  };
};
