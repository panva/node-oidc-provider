const { createHash } = require('crypto');

const { jwtVerify } = require('jose/jwt/verify'); // eslint-disable-line import/no-unresolved
const { EmbeddedJWK } = require('jose/jwk/embedded'); // eslint-disable-line import/no-unresolved
const { calculateThumbprint } = require('jose/jwk/thumbprint'); // eslint-disable-line import/no-unresolved

const { InvalidDpopProof } = require('./errors');
const instance = require('./weak_cache');
const base64url = require('./base64url');

module.exports = async (ctx, accessToken) => {
  const {
    clockTolerance,
    features: { dPoP: dPoPConfig },
    dPoPSigningAlgValues,
  } = instance(ctx.oidc.provider).configuration();

  if (!dPoPConfig.enabled) {
    return undefined;
  }

  const token = ctx.get('DPoP');

  if (!token) {
    return undefined;
  }

  try {
    let jwk;
    const { payload } = await jwtVerify(
      token,
      (...args) => {
        ([{ jwk }] = args);
        return EmbeddedJWK(...args);
      },
      {
        maxTokenAge: `${dPoPConfig.iatTolerance} seconds`,
        clockTolerance,
        algorithms: dPoPSigningAlgValues,
        typ: 'dpop+jwt',
      },
    );

    if (typeof payload.jti !== 'string' || !payload.jti) {
      throw new Error('must have a jti string property');
    }

    if (payload.htm !== ctx.method) {
      throw new Error('htm mismatch');
    }

    if (payload.htu !== ctx.oidc.urlFor(ctx.oidc.route)) {
      throw new Error('htu mismatch');
    }

    if (accessToken) {
      const ath = base64url.encode(createHash('sha256').update(accessToken).digest());
      if (payload.ath !== ath) {
        throw new Error('ath mismatch');
      }
    }

    const thumbprint = await calculateThumbprint(jwk);

    return { thumbprint, jti: payload.jti, iat: payload.iat };
  } catch (err) {
    throw new InvalidDpopProof('invalid DPoP key binding', err.message);
  }
};
