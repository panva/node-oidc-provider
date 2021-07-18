const { strict: assert } = require('assert');
const crypto = require('crypto');

const paseto = require('paseto');

const instance = require('../../helpers/weak_cache');
const nanoid = require('../../helpers/nanoid');
const ctxRef = require('../ctx_ref');
const isPlainObject = require('../../helpers/_/is_plain_object');

module.exports = (provider, { opaque }) => {
  async function getResourceServerConfig(token) {
    const { keystore } = instance(provider);

    if (!token.resourceServer || !isPlainObject(token.resourceServer.paseto)) {
      throw new Error('missing "paseto" Resource Server configuration');
    }

    const { version, purpose } = token.resourceServer.paseto;
    let { key, kid } = token.resourceServer.paseto;

    if (version !== 1 && version !== 2) {
      throw new Error('unsupported "paseto.version"');
    }

    if (purpose === 'local' && version === 1) {
      if (key === undefined) {
        throw new Error('local purpose PASETO Resource Server requires a "paseto.key"');
      }
      if (!(key instanceof crypto.KeyObject)) {
        key = crypto.createSecretKey(key);
      }
      if (key.type !== 'secret' || key.symmetricKeySize !== 32) {
        throw new Error('local purpose PASETO Resource Server "paseto.key" must be 256 bits long secret key');
      }
    } else if (purpose === 'public') {
      if (version === 1) {
        [key] = keystore.selectForSign({ alg: 'PS384', kid });
      } else if (version === 2) {
        [key] = keystore.selectForSign({ alg: 'EdDSA', crv: 'Ed25519', kid });
      }
      if (!key) {
        throw new Error('resolved Resource Server paseto configuration has no corresponding key in the provider\'s keystore');
      }
      kid = key.kid;
      key = await keystore.getKeyObject(key, version === 1 ? 'RS384' : 'EdDSA').catch(() => {
        throw new Error(`provider key (kid: ${kid}) is invalid`);
      });
    } else {
      throw new Error('unsupported PASETO version and purpose');
    }

    if (kid !== undefined && typeof kid !== 'string') {
      throw new Error('paseto.kid must be a string when provided');
    }
    return {
      version, purpose, key, kid,
    };
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
        assert(client && client.clientId === clientId);
        if (client.subjectType === 'pairwise') {
          const pairwiseIdentifier = instance(provider).configuration('pairwiseIdentifier');
          sub = await pairwiseIdentifier(ctx, sub, client);
        }
      }

      const tokenPayload = {
        ...extra,
        jti,
        sub: sub || clientId,
        iat: new Date(iat * 1000),
        exp: new Date(exp * 1000),
        scope,
        client_id: clientId,
        iss: provider.issuer,
        aud,
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
        footer: undefined,
        payload: tokenPayload,
      };

      const customizer = instance(provider).configuration('formats.customizers.paseto');
      if (customizer) {
        await customizer(ctx, this, structuredToken);
      }

      if (!structuredToken.payload.aud) {
        throw new Error('JWT Access Tokens must contain an audience, for Access Tokens without audience (only usable at the userinfo_endpoint) use an opaque format');
      }

      const config = await getResourceServerConfig(this);

      let issue;
      if (config.version === 1) {
        issue = config.purpose === 'local' ? paseto.V1.encrypt : paseto.V1.sign;
      } else {
        issue = paseto.V2.sign;
      }

      /* eslint-disable no-unused-expressions */
      if (config.kid) {
        structuredToken.footer || (structuredToken.footer = {});
        structuredToken.footer.kid || (structuredToken.footer.kid = config.kid);
      }

      if (config.purpose === 'local') {
        structuredToken.footer || (structuredToken.footer = {});
        structuredToken.footer.iss || (structuredToken.footer.iss = provider.issuer);
        structuredToken.footer.aud || (structuredToken.footer.aud = structuredToken.payload.aud);
      }
      /* eslint-enable no-unused-expressions */

      const token = await issue(
        structuredToken.payload,
        config.key,
        {
          footer: structuredToken.footer ? JSON.stringify(structuredToken.footer) : undefined,
          iat: false,
        },
      );

      return { value: token };
    },
  };
};
