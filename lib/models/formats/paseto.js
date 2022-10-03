const { strict: assert } = require('assert');
const crypto = require('crypto');

let paseto;
let paseto3 = parseInt(process.versions.node, 10) >= 16;

if (paseto3) {
  try {
    // eslint-disable-next-line
    paseto = require('paseto3');
  } catch (err) {
    paseto3 = false;
  }
}

if (!paseto3) {
  // eslint-disable-next-line
  paseto = require('paseto');
}

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
    let alg;

    if (version > 2 && !paseto3) {
      throw new Error('PASETO v3 and v4 tokens are only supported in Node.js >= 16.0.0 runtimes');
    }

    switch (true) {
      case version === 1 && purpose === 'local':
      case version === 3 && purpose === 'local':
        if (!key) {
          throw new Error('local purpose PASETO Resource Server requires a "paseto.key"');
        }
        if (!(key instanceof crypto.KeyObject)) {
          key = crypto.createSecretKey(key);
        }
        if (key.type !== 'secret' || key.symmetricKeySize !== 32) {
          throw new Error('local purpose PASETO Resource Server "paseto.key" must be 256 bits long secret key');
        }
        break;
      case version === 1 && purpose === 'public':
        alg = 'PS384';
        [key] = keystore.selectForSign({
          alg, kid, kty: 'RSA',
        });
        break;
      case (version === 2 || version === 4) && purpose === 'public':
        alg = 'EdDSA';
        [key] = keystore.selectForSign({
          alg, crv: 'Ed25519', kid, kty: 'OKP',
        });
        break;
      case version === 3 && purpose === 'public':
        alg = 'ES384';
        [key] = keystore.selectForSign({
          alg, crv: 'P-384', kid, kty: 'EC',
        });
        break;
      default:
        throw new Error('unsupported PASETO version and purpose');
    }

    if (purpose === 'public') {
      if (!key) {
        throw new Error('resolved Resource Server paseto configuration has no corresponding key in the provider\'s keystore');
      }
      ({ kid } = key);
      // eslint-disable-next-line no-nested-ternary
      key = await keystore.getKeyObject(key, alg).catch(() => {
        throw new Error(`provider key (kid: ${kid}) is invalid`);
      });
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
        assertion: undefined,
      };

      const customizer = instance(provider).configuration('formats.customizers.paseto');
      if (customizer) {
        await customizer(ctx, this, structuredToken);
      }

      if (!structuredToken.payload.aud) {
        throw new Error('PASETO Access Tokens must contain an audience, for Access Tokens without audience (only usable at the userinfo_endpoint) use an opaque format');
      }

      const {
        version, purpose, kid, key,
      } = await getResourceServerConfig(this);

      let issue;
      // eslint-disable-next-line default-case
      switch (version) {
        case 1:
          issue = purpose === 'local' ? paseto.V1.encrypt : paseto.V1.sign;
          break;
        case 2:
          issue = paseto.V2.sign;
          break;
        case 3:
          issue = purpose === 'local' ? paseto.V3.encrypt : paseto.V3.sign;
          break;
        case 4:
          issue = paseto.V4.sign;
          break;
      }

      if (structuredToken.assertion !== undefined && version < 3) {
        throw new Error('only PASETO v3 and v4 tokens support an implicit assertion');
      }

      /* eslint-disable no-unused-expressions */
      if (kid) {
        structuredToken.footer || (structuredToken.footer = {});
        structuredToken.footer.kid || (structuredToken.footer.kid = kid);
      }

      if (purpose === 'local') {
        structuredToken.footer || (structuredToken.footer = {});
        structuredToken.footer.iss || (structuredToken.footer.iss = provider.issuer);
        structuredToken.footer.aud || (structuredToken.footer.aud = structuredToken.payload.aud);
      }
      /* eslint-enable no-unused-expressions */

      const token = await issue(
        structuredToken.payload,
        key,
        {
          footer: structuredToken.footer ? JSON.stringify(structuredToken.footer) : undefined,
          iat: false,
          assertion: structuredToken.assertion ? structuredToken.assertion : undefined,
        },
      );

      return { value: token };
    },
  };
};
