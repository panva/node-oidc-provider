const { strict: assert } = require('assert');
const { createPrivateKey } = require('crypto');

const runtimeSupport = require('../../helpers/runtime_support');
const paseto = require('../../helpers/paseto');
const instance = require('../../helpers/weak_cache');
const nanoid = require('../../helpers/nanoid');
const ctxRef = require('../ctx_ref');

module.exports = (provider, { opaque }) => {
  let key;
  let kid;

  function getSigningKey() {
    const { keystore } = instance(provider);
    const jwk = keystore.all({ use: 'sig', kty: 'OKP', alg: 'EdDSA' }).find((x) => x.crv === 'Ed25519');

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
      if (!runtimeSupport.EdDSA) {
        throw new Error('paseto structured tokens can only be enabled on Node.js >= 12.0.0 runtime');
      }
      const [, payload] = await opaque.getValueAndPayload.call(this);
      const {
        jti, iat, exp, scope, clientId, 'x5t#S256': x5t, 'jkt#S256': jkt, extra,
      } = payload;
      let { aud, accountId: sub } = payload;

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

        const ctx = ctxRef.get(this);

        if (sub) {
          // TODO: in v7.x require token.client to be set
          const client = this.client || await provider.Client.find(clientId);
          assert(client && client.clientId === clientId);
          if (client.sectorIdentifier) {
            const pairwiseIdentifier = instance(provider).configuration('pairwiseIdentifier');
            sub = await pairwiseIdentifier(ctx, sub, client);
          }
        }

        const tokenPayload = {
          ...extra,
          jti,
          sub: sub || clientId,
          kid,
          iat: iat ? new Date(iat * 1000).toISOString() : undefined,
          exp: exp ? new Date(exp * 1000).toISOString() : undefined,
          scope,
          client_id: clientId,
          iss: provider.issuer,
          ...(aud ? { aud } : { aud: clientId }),
          ...(x5t || jkt ? { cnf: {} } : undefined),
          // TODO: make auth_time, acr, amr available
        };

        if (x5t) {
          tokenPayload.cnf['x5t#S256'] = x5t;
        }
        if (jkt) {
          tokenPayload.cnf['jkt#S256'] = jkt;
        }

        const structuredToken = {
          payload: tokenPayload,
          footer: undefined,
        };

        const customizer = instance(provider).configuration('formats.customizers.paseto');
        if (customizer) {
          await customizer(ctx, this, structuredToken);
        }

        value = await paseto.sign(structuredToken, key);
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
        assert.equal(token, stored.paseto);
        jti = this.getTokenId(token);
      }
      return opaque.verify.call(this, jti, stored, { ignoreExpiration, foundByReference });
    },
  };
};
