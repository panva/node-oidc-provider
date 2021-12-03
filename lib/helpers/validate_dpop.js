const { createHash } = require('crypto');

const {
  jwtVerify,
  EmbeddedJWK,
  calculateJwkThumbprint,
} = require('jose');

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
        maxTokenAge: dPoPConfig.iatTolerance,
        clockTolerance,
        algorithms: dPoPSigningAlgValues,
        typ: 'dpop+jwt',
      },
    );

    if (typeof payload.jti !== 'string' || !payload.jti) {
      throw new InvalidDpopProof('DPoP Proof must have a jti string property');
    }

    if (payload.htm !== ctx.method) {
      throw new InvalidDpopProof('DPoP Proof htm mismatch');
    }

    if (payload.htu !== ctx.oidc.urlFor(ctx.oidc.route)) {
      throw new InvalidDpopProof('DPoP Proof htu mismatch');
    }

    if (accessToken) {
      const ath = base64url.encode(createHash('sha256').update(accessToken).digest());
      if (payload.ath !== ath) {
        throw new InvalidDpopProof('DPoP Proof ath mismatch');
      }
    }

    const thumbprint = await calculateJwkThumbprint(jwk);

    return { thumbprint, jti: payload.jti, iat: payload.iat };
  } catch (err) {
    if (err instanceof InvalidDpopProof) {
      throw err;
    }
    throw new InvalidDpopProof('invalid DPoP key binding', err.message);
  }
};
