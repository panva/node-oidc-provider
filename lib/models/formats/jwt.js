const { strict: assert } = require('assert');

const JWT = require('../../helpers/jwt');
const instance = require('../../helpers/weak_cache');
const nanoid = require('../../helpers/nanoid');
const base64url = require('../../helpers/base64url');
const ctxRef = require('../ctx_ref');

function getClaim(token, claim) {
  return JSON.parse(base64url.decode(token.split('.')[1]))[claim];
}

module.exports = (provider, { opaque }) => {
  async function getSigningAlgAndKey(ctx, token, clientId) {
    let client;
    if (clientId) { // TODO: in v7.x require token.client to be set
      client = token.client || await provider.Client.find(clientId);
      assert(client && client.clientId === clientId);
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
    getSigningAlgAndKey, // returning for it being reused via jwt_ietf

    generateTokenId() {
      return nanoid();
    },
    async getValueAndPayload() {
      const [, payload] = await opaque.getValueAndPayload.call(this);
      const {
        jti, iat, exp, scope, aud, clientId: azp, 'x5t#S256': x5t, 'jkt#S256': jkt, extra,
      } = payload;
      let { accountId: sub } = payload;

      let value;
      if (this.jwt) {
        value = this.jwt;
      } else {
        const ctx = ctxRef.get(this);
        const { key, alg } = await getSigningAlgAndKey(ctx, this, azp);

        if (sub) {
          // TODO: in v7.x require token.client to be set
          const client = this.client || await provider.Client.find(azp);
          assert(client && client.clientId === azp);
          if (client.sectorIdentifier) {
            const pairwiseIdentifier = instance(provider).configuration('pairwiseIdentifier');
            sub = await pairwiseIdentifier(ctx, sub, client);
          }
        }

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

        const structuredToken = {
          header: undefined,
          payload: tokenPayload,
        };

        const customizer = instance(provider).configuration('formats.customizers.jwt');
        if (customizer) {
          await customizer(ctx, this, structuredToken);
        }

        value = await JWT.sign(structuredToken.payload, key, alg, {
          fields: structuredToken.header,
        });
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
