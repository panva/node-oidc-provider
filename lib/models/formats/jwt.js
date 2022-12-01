import * as crypto from 'node:crypto';

import * as JWT from '../../helpers/jwt.js';
import instance from '../../helpers/weak_cache.js';
import nanoid from '../../helpers/nanoid.js';
import ctxRef from '../ctx_ref.js';

export default (provider, { opaque }) => {
  async function getResourceServerConfig(token) {
    const { keystore, configuration } = instance(provider);
    const { clientDefaults: { id_token_signed_response_alg: defaultAlg } } = configuration();

    let sign;
    let encrypt;

    {
      let alg;
      let key;
      let kid;

      if (token.resourceServer) {
        if (token.resourceServer.jwt?.sign) {
          ({ alg = defaultAlg, key, kid } = token.resourceServer.jwt.sign);
        } else if (
          !token.resourceServer.jwt
          || (!token.resourceServer.jwt.sign && !token.resourceServer.jwt.encrypt)
        ) {
          alg = defaultAlg;
        }
      }

      if (alg === 'none') {
        throw new Error('JWT Access Tokens may not use JWS algorithm "none"');
      } else if (alg) {
        if (alg.startsWith('HS')) {
          if (!key) {
            throw new Error('missing jwt.sign.key Resource Server configuration');
          }
          if (!(key instanceof crypto.KeyObject)) {
            key = crypto.createSecretKey(key);
          }
          if (key.type !== 'secret') {
            throw new Error('jwt.sign.key Resource Server configuration must be a secret (symmetric) key');
          }
        } else {
          [key] = keystore.selectForVerify({ alg, use: 'sig', kid });
          if (!key) {
            throw new Error('resolved Resource Server jwt configuration has no corresponding key in the provider\'s keystore');
          }
          kid = key.kid;
          key = await keystore.getKeyObject(key, alg).catch(() => {
            throw new Error(`provider key (kid: ${kid}) is invalid`);
          });
        }
        if (kid !== undefined && typeof kid !== 'string') {
          throw new Error('jwt.sign.kid must be a string when provided');
        }
        sign = { alg, key, kid };
      }
    }

    if (token.resourceServer?.jwt?.encrypt) {
      const { alg, enc, kid } = token.resourceServer.jwt.encrypt;
      let { key } = token.resourceServer.jwt.encrypt;

      if (!alg) {
        throw new Error('missing jwt.encrypt.alg Resource Server configuration');
      }
      if (!enc) {
        throw new Error('missing jwt.encrypt.enc Resource Server configuration');
      }
      if (!key) {
        throw new Error('missing jwt.encrypt.key Resource Server configuration');
      }

      if (!(key instanceof crypto.KeyObject) && /^(A|dir$)/.test(alg)) {
        key = crypto.createSecretKey(key);
      }

      if (key.type === 'private') throw new Error('jwt.encrypt.key Resource Server configuration must be a secret (symmetric) or a public key');
      if (key.type === 'public' && !sign) throw new Error('missing jwt.sign Resource Server configuration');

      if (kid !== undefined && typeof kid !== 'string') {
        throw new Error('jwt.encrypt.kid must be a string when provided');
      }
      encrypt = {
        alg, enc, key, kid,
      };
    }

    return { sign, encrypt };
  }

  return {
    generateTokenId() {
      return nanoid();
    },
    async getValueAndPayload() {
      const { payload } = await opaque.getValueAndPayload.call(this);
      const {
        aud, jti, iat, exp, scope, clientId, 'x5t#S256': x5t, jkt, extra,
      } = payload;
      let { accountId: sub } = payload;

      const ctx = ctxRef.get(this);

      if (sub) {
        const { client } = this;
        if (client?.clientId !== clientId) {
          throw new TypeError('clientId and client mismatch');
        }
        if (client.subjectType === 'pairwise') {
          const pairwiseIdentifier = instance(provider).configuration('pairwiseIdentifier');
          sub = await pairwiseIdentifier(ctx, sub, client);
        }
      }

      const tokenPayload = {
        ...extra,
        jti,
        sub: sub || clientId,
        iat,
        exp,
        scope,
        client_id: clientId,
        iss: provider.issuer,
        aud,
        ...(x5t || jkt ? { cnf: {} } : undefined),
      };

      if (x5t) {
        tokenPayload.cnf['x5t#S256'] = x5t;
      }
      if (jkt) {
        tokenPayload.cnf.jkt = jkt;
      }

      const structuredToken = {
        header: undefined,
        payload: tokenPayload,
      };

      const customizer = instance(provider).configuration('formats.customizers.jwt');
      if (customizer) {
        await customizer(ctx, this, structuredToken);
      }

      if (!structuredToken.payload.aud) {
        throw new Error('JWT Access Tokens must contain an audience, for Access Tokens without audience (only usable at the userinfo_endpoint) use an opaque format');
      }

      const config = await getResourceServerConfig(this);

      let signed;
      if (config.sign) {
        signed = await JWT.sign(structuredToken.payload, config.sign.key, config.sign.alg, {
          typ: 'at+jwt',
          fields: { kid: config.sign.kid, ...structuredToken.header },
        });
      }

      if (config.sign && config.encrypt) {
        const encrypted = await JWT.encrypt(signed, config.encrypt.key, {
          fields: {
            kid: config.encrypt.kid,
            iss: provider.issuer,
            aud: structuredToken.payload.aud,
            cty: 'at+jwt',
          },
          enc: config.encrypt.enc,
          alg: config.encrypt.alg,
        });

        return { value: encrypted };
      }

      if (config.sign) {
        return { value: signed };
      }

      if (config.encrypt) {
        const cleartext = JSON.stringify(structuredToken.payload);
        const encrypted = await JWT.encrypt(cleartext, config.encrypt.key, {
          fields: {
            kid: config.encrypt.kid,
            iss: provider.issuer,
            aud: structuredToken.payload.aud,
            typ: 'at+jwt',
            ...structuredToken.header,
          },
          enc: config.encrypt.enc,
          alg: config.encrypt.alg,
        });

        return { value: encrypted };
      }

      throw new Error('invalid Resource Server jwt configuration');
    },
  };
};
