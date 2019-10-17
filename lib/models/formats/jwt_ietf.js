const { strict: assert } = require('assert');

const instance = require('../../helpers/weak_cache');
const JWT = require('../../helpers/jwt');
const ctxRef = require('../ctx_ref');

const PROPERTY = 'jwt-ietf';

module.exports = (provider, { opaque, jwt }) => ({
  generateTokenId: jwt.generateTokenId,
  getTokenId: jwt.getTokenId,
  async getValueAndPayload() {
    const [, payload] = await opaque.getValueAndPayload.call(this);
    const {
      jti, iat, exp, scope, clientId, 'x5t#S256': x5t, jkt, extra,
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
    if (this[PROPERTY]) {
      value = this[PROPERTY];
    } else {
      const ctx = ctxRef.get(this);
      const { key, alg } = await jwt.getSigningAlgAndKey(ctx, this, clientId);

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
        iat,
        exp,
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
        tokenPayload.cnf.jkt = jkt;
      }

      const structuredToken = {
        header: undefined,
        payload: tokenPayload,
      };

      const customizer = instance(provider).configuration('formats.customizers.jwt-ietf');
      if (customizer) {
        await customizer(ctx, this, structuredToken);
      }

      value = await JWT.sign(structuredToken.payload, key, alg, {
        typ: 'at+jwt', fields: structuredToken.header,
      });
    }
    payload[PROPERTY] = value;

    return [value, payload];
  },
  async verify(token, stored, { ignoreExpiration, foundByReference }) {
    let jti;
    if (!foundByReference) {
      assert.equal(token, stored[PROPERTY]);
      jti = this.getTokenId(token);
    }
    return opaque.verify.call(this, jti, stored, { ignoreExpiration, foundByReference });
  },
});
