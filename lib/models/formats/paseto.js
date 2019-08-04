const assert = require('assert');
const { createPrivateKey } = require('crypto');

const paseto = require('../../helpers/paseto');
const instance = require('../../helpers/weak_cache');
const nanoid = require('../../helpers/nanoid');

const opaqueFormat = require('./opaque');

module.exports = (provider) => {
  const opaque = opaqueFormat(provider);

  let key;
  let kid;

  function getSigningKey() {
    const { keystore } = instance(provider);
    const jwk = keystore.all({ use: 'sig', kty: 'OKP', alg: 'EdDSA' }).find(x => x.crv === 'Ed25519');

    if (!jwk) {
      throw new Error('No Ed25519 signing key found to sign the PASETO formatted token with');
    }

    key = createPrivateKey(jwk.toPEM(true));
    ({ kid } = jwk);
  }

  return {
    generateTokenId() {
      return nanoid();
    },
    async getValueAndPayload() {
      const [, payload] = await opaque.getValueAndPayload.call(this);
      const {
        jti, accountId: sub, iat, exp, scope, clientId: azp, 'x5t#S256': x5t, 'jkt#S256': jkt, extra,
      } = payload;
      let { aud } = payload;

      if (Array.isArray(aud)) {
        if (aud.length > 1) {
          throw new Error('only a single audience ("aud") value is permitted for this token type');
        } else {
          [aud] = aud;
        }
      }

      let value;
      if (this.paseto) {
        value = this.paseto;
      } else {
        if (!key) {
          getSigningKey();
        }

        const tokenPayload = {
          ...extra,
          jti,
          sub,
          kid,
          iat: iat ? new Date(iat * 1000).toISOString() : undefined,
          exp: exp ? new Date(exp * 1000).toISOString() : undefined,
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

        value = await paseto.sign(tokenPayload, key);
      }
      payload.paseto = value;

      return [value, payload];
    },
    getTokenId(token) {
      return paseto.decode(token).jti;
    },
    async verify(token, stored, { ignoreExpiration, foundByReference }) {
      let jti;
      if (!foundByReference) {
        assert.deepEqual(token, stored.paseto);
        jti = this.getTokenId(token);
      }
      return opaque.verify.call(this, jti, stored, { ignoreExpiration, foundByReference });
    },
  };
};
