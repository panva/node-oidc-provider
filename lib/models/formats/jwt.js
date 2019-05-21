const assert = require('assert');

const base64url = require('base64url');

const JWT = require('../../helpers/jwt');
const instance = require('../../helpers/weak_cache');
const nanoid = require('../../helpers/nanoid');
const ctxRef = require('../ctx_ref');

const opaqueFormat = require('./opaque');

function getClaim(token, claim) {
  return JSON.parse(base64url.decode(token.split('.')[1]))[claim];
}

module.exports = (provider) => {
  const opaque = opaqueFormat(provider);

  async function getSigningAlgAndKey(clientId) {
    let alg = 'RS256';
    let client;
    if (clientId) {
      client = await provider.Client.find(clientId);
      assert(client);
      if (client.idTokenSignedResponseAlg !== 'none' && !client.idTokenSignedResponseAlg.startsWith('HS')) {
        alg = client.idTokenSignedResponseAlg;
      }
    }

    const { keystore } = instance(provider);
    const key = keystore.get({ alg, use: 'sig' });

    return { key, alg };
  }

  return {
    generateTokenId() {
      return nanoid();
    },
    async getValueAndPayload() {
      const [, payload] = await opaque.getValueAndPayload.call(this);
      const {
        jti, accountId: sub, iat, exp, scope, aud, clientId: azp, 'x5t#S256': S256,
      } = payload;

      let value;
      if (this.jwt) {
        value = this.jwt;
      } else {
        const { key, alg } = await getSigningAlgAndKey(azp);
        value = await JWT.sign({
          ...await instance(provider).configuration('formats.extraJwtAccessTokenClaims')(ctxRef.get(this), this),
          jti,
          sub,
          iat,
          exp,
          scope,
          iss: provider.issuer,
          ...(S256 ? { cnf: { 'x5t#S256': S256 } } : undefined),
          ...(aud ? { aud, azp } : { aud: azp }),
        }, key, alg);
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
        assert.deepEqual(token, stored.jwt);
        jti = this.getTokenId(token);
      }
      return opaque.verify.call(this, jti, stored, { ignoreExpiration, foundByReference });
    },
  };
};
