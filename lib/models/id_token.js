/* eslint-disable no-unused-expressions */
import { format } from 'node:util';

import { generate as tokenHash } from 'oidc-token-hash';

import merge from '../helpers/_/merge.js';
import epochTime from '../helpers/epoch_time.js';
import * as JWT from '../helpers/jwt.js';
import { InvalidClientMetadata } from '../helpers/errors.js';
import instance from '../helpers/weak_cache.js';
import isPlainObject from '../helpers/_/is_plain_object.js';

const hashes = ['at_hash', 'c_hash', 's_hash', 'urn:openid:params:jwt:claim:rt_hash'];

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
          key = await client.symmetricKeyStore.getKeyObject(jwk, alg);
        } else {
          [jwk] = instance(provider).keystore.selectForSign({ alg, use: 'sig' });
          key = await instance(provider).keystore.getKeyObject(jwk, alg).catch(() => {
            throw new Error(`provider key (kid: ${jwk.kid}) is invalid`);
          });
        }

        if (use === 'idtoken') {
          hashes.forEach((claim) => {
            if (payload[claim]) {
              payload[claim] = tokenHash(payload[claim], alg, jwk.crv);
            }
          });
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
        jwk && (encryptionKey = await client.symmetricKeyStore.getKeyObject(jwk, encryption.enc));
      } else if (encryption.alg.startsWith('A')) {
        [jwk] = client.symmetricKeyStore.selectForEncrypt({ alg: encryption.alg, use: 'enc' });
        jwk && (encryptionKey = await client.symmetricKeyStore.getKeyObject(jwk, encryption.alg));
      } else {
        await client.asymmetricKeyStore.refresh();
        [jwk] = client.asymmetricKeyStore.selectForEncrypt({ alg: encryption.alg, use: 'enc' });
        jwk && (encryptionKey = await client.asymmetricKeyStore.getKeyObject(jwk, encryption.alg));
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
        clockTolerance: instance(provider).configuration('clockTolerance'),
        algorithm: alg,
        subject: true,
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
}
