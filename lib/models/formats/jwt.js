const { strict: assert } = require('assert');

const JWT = require('../../helpers/jwt');
const instance = require('../../helpers/weak_cache');
const nanoid = require('../../helpers/nanoid');
const base64url = require('../../helpers/base64url');
const ctxRef = require('../ctx_ref');

const opaqueFormat = require('./opaque');

function getClaim(token, claim) {
  return JSON.parse(base64url.decode(token.split('.')[1]))[claim];
}

module.exports = (provider) => {
  const opaque = opaqueFormat(provider);

  async function getSigningAlgAndKey(ctx, token, clientId) {
    let client;
    if (clientId) {
      client = await provider.Client.find(clientId);
      assert(client);
    }

    const { keystore, configuration } = instance(provider);
    const { formats: { jwtAccessTokenSigningAlg } } = configuration();

    const alg = await jwtAccessTokenSigningAlg(ctx, token, client);

    if (alg === 'none' || alg.startsWith('HS')) {
      throw new Error('JWT Access Tokens may not use JWA HMAC algorithms or "none"');
    }

    const key = keystore.get({ alg, use: 'sig' });

    if (!key) {
      throw new Error('invalid alg resolved for JWT Access Token signature, the alg must be an asymmetric one that the provider has in its keystore');
    }

    return { key, alg };
  }

  return {
    generateTokenId() {
      return nanoid();
    },
    async getValueAndPayload() {
      const [, payload] = await opaque.getValueAndPayload.call(this);
      const {
        jti, accountId: sub, iat, exp, scope, aud, clientId: azp, 'x5t#S256': x5t, 'jkt#S256': jkt, extra,
      } = payload;

      let value;
      if (this.jwt) {
        value = this.jwt;
      } else {
        const ctx = ctxRef.get(this);
        const { key, alg } = await getSigningAlgAndKey(ctx, this, azp);
        const tokenPayload = {
          ...extra,
          jti,
          sub,
          iat,
          exp,
          scope,
          iss: provider.issuer,
          ...(aud ? { aud, azp } : { aud: azp }),
          ...(x5t || jkt ? { cnf: {} } : undefined),
        };

        if (x5t) {
          tokenPayload.cnf['x5t#S256'] = x5t;
        }
        if (jkt) {
          tokenPayload.cnf['jkt#S256'] = jkt;
        }

        value = await JWT.sign(tokenPayload, key, alg);
      }
      payload.jwt = value;

      return [value, payload];
    },
    getTokenId(token) {
      return getClaim(token, 'jti');
    },
    async verify(token, stored, { ignoreExpiration, foundByReference }) {
      let jti;
      if (!foundByReference) {
        assert.equal(token, stored.jwt);
        jti = this.getTokenId(token);
      }
      return opaque.verify.call(this, jti, stored, { ignoreExpiration, foundByReference });
    },
  };
};
