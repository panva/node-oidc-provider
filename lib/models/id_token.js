/* eslint-disable no-unused-expressions */
import { format } from 'node:util';
import * as crypto from 'node:crypto';

import merge from '../helpers/_/merge.js';
import epochTime from '../helpers/epoch_time.js';
import * as JWT from '../helpers/jwt.js';
import { InvalidClientMetadata } from '../helpers/errors.js';
import instance from '../helpers/weak_cache.js';
import isPlainObject from '../helpers/_/is_plain_object.js';

const hashes = ['at_hash', 'c_hash', 's_hash'];

function getHashArgs(alg) {
  switch (alg) {
    case 'RS256':
    case 'PS256':
    case 'ES256':
    case 'HS256':
      return 'sha256';
    case 'RS384':
    case 'PS384':
    case 'ES384':
    case 'HS384':
      return 'sha384';
    case 'RS512':
    case 'PS512':
    case 'ES512':
    case 'HS512':
    case 'Ed25519':
    case 'EdDSA': // alias for Ed25519, Ed448 is not supported
      return 'sha512';
    case 'ML-DSA-44':
    case 'ML-DSA-65':
    case 'ML-DSA-87':
      return ['shake256', { outputLength: 64 }];
    default:
      throw new Error('not implemented');
  }
}

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

export default function getIdToken(provider) {
  return class IdToken {
    constructor(available, { ctx, client = ctx ? ctx.oidc.client : undefined }) {
      if (!isPlainObject(available)) {
        throw new TypeError('expected claims to be an object, are you sure claims() method resolves with or returns one?');
      }
      this.extra = {};
      this.available = available;
      this.client = client;
      this.ctx = ctx;
    }

    static expiresIn(...args) {
      const ttl = instance(provider).configuration.ttl[this.name];

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

      return merge({}, await mask.result(), this.extra);
    }

    async issue({ use, expiresAt = null } = {}) {
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
            typ: 'logout+jwt',
            expiresIn: 120,
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
            audience: client.clientId,
            issuer: provider.issuer,
            typ: 'token-introspection+jwt',
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
            expiresIn: 120,
            issuer: provider.issuer,
            noIat: true,
          };
          encryption = {
            alg: client.authorizationEncryptedResponseAlg,
            enc: client.authorizationEncryptedResponseEnc,
          };
          break;
        default:
          throw new TypeError('invalid use option');
      }

      const signed = await (async () => {
        if (typeof alg !== 'string') {
          throw new Error();
        }
        let jwk;
        let key;
        if (alg.startsWith('HS')) {
          if (use !== 'authorization') { // handled in checkResponseMode
            client.checkClientSecretExpiration(format(messages.sig[use], alg));
          }
          [jwk] = client.symmetricKeyStore.selectForSign({ alg, use: 'sig' });
          key = client.symmetricKeyStore.getKeyObject(jwk);
        } else {
          [jwk] = instance(provider).keystore.selectForSign({ alg, use: 'sig' });
          key = instance(provider).keystore.getKeyObject(jwk);
        }

        if (use === 'idtoken') {
          const digest = getHashArgs(alg);
          for (const claim of hashes) {
            if (payload[claim]) {
              const hash = typeof digest === 'string'
                ? crypto.hash(digest, payload[claim], 'buffer')
                : crypto.createHash(...digest).update(payload[claim]).digest();
              payload[claim] = hash.subarray(0, hash.byteLength / 2).toString('base64url');
            }
          }
        }

        if (jwk) {
          signOptions.fields = { kid: jwk.kid };
        }

        return JWT.sign(payload, key, alg, signOptions);
      })();

      if (!encryption.enc) {
        return signed;
      }

      if (/^(A|dir$)/.test(encryption.alg)) {
        if (use !== 'authorization') { // handled in checkResponseMode
          client.checkClientSecretExpiration(format(messages.enc[use], encryption.alg));
        }
      }

      let jwk;
      let encryptionKey;
      if (encryption.alg === 'dir') {
        [jwk] = client.symmetricKeyStore.selectForEncrypt({ alg: encryption.enc, use: 'enc' });
        jwk && (encryptionKey = client.symmetricKeyStore.getKeyObject(jwk, true));
      } else if (encryption.alg.startsWith('A')) {
        [jwk] = client.symmetricKeyStore.selectForEncrypt({ alg: encryption.alg, use: 'enc' });
        jwk && (encryptionKey = client.symmetricKeyStore.getKeyObject(jwk, true));
      } else {
        await client.asymmetricKeyStore.refresh();
        [jwk] = client.asymmetricKeyStore.selectForEncrypt({ alg: encryption.alg, use: 'enc' });
        jwk && (encryptionKey = client.asymmetricKeyStore.getKeyObject(jwk, true));
      }

      if (!encryptionKey) {
        throw new InvalidClientMetadata(`no suitable encryption key found (${encryption.alg})`);
      }

      const { kid } = jwk;

      return JWT.encrypt(signed, encryptionKey, {
        enc: encryption.enc,
        alg: encryption.alg,
        fields: {
          cty: 'JWT',
          kid,
          iss: signOptions.issuer,
          aud: signOptions.audience,
        },
      });
    }

    static async validate(jwt, client) {
      const alg = client.idTokenSignedResponseAlg;

      let keyOrStore;
      if (alg.startsWith('HS')) {
        client.checkClientSecretExpiration('client secret is expired - cannot validate ID Token Hint');
        keyOrStore = client.symmetricKeyStore;
      } else {
        keyOrStore = instance(provider).keystore;
      }

      const opts = {
        ignoreExpiration: true,
        audience: client.clientId,
        issuer: provider.issuer,
        clockTolerance: instance(provider).configuration.clockTolerance,
        algorithm: alg,
        subject: true,
      };

      return JWT.verify(jwt, keyOrStore, opts);
    }
  };
}
