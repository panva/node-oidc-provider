const { createHash } = require('crypto');
const { URL } = require('url');

const {
  jwtVerify,
  EmbeddedJWK,
  calculateJwkThumbprint,
} = require('jose');

const { InvalidDpopProof } = require('./errors');
const instance = require('./weak_cache');
const base64url = require('./base64url');
const epochTime = require('./epoch_time');

module.exports = async (ctx, accessToken) => {
  const {
    features: { dPoP: dPoPConfig },
    dPoPSigningAlgValues,
  } = instance(ctx.oidc.provider).configuration();

  if (!dPoPConfig.enabled) {
    return undefined;
  }

  const proof = ctx.get('DPoP');

  if (!proof) {
    return undefined;
  }

  let payload;
  let protectedHeader;
  try {
    ({ protectedHeader, payload } = await jwtVerify(proof, EmbeddedJWK, { algorithms: dPoPSigningAlgValues, typ: 'dpop+jwt' }));

    if (typeof payload.iat !== 'number' || !payload.iat) {
      throw new InvalidDpopProof('DPoP proof must have a iat number property');
    }

    if (typeof payload.jti !== 'string' || !payload.jti) {
      throw new InvalidDpopProof('DPoP proof must have a jti string property');
    }

    const now = epochTime();
    const diff = Math.abs(now - payload.iat);
    if (diff > 60) {
      throw new InvalidDpopProof('DPoP proof iat is not recent enough');
    }

    if (payload.htm !== ctx.method) {
      throw new InvalidDpopProof('DPoP proof htm mismatch');
    }

    {
      const expected = ctx.oidc.urlFor(ctx.oidc.route);
      let actual;
      try {
        actual = new URL(payload.htu);
        actual.hash = '';
        actual.search = '';
      } catch {}

      if (actual?.href !== expected) {
        throw new InvalidDpopProof('DPoP proof htu mismatch');
      }
    }

    if (accessToken) {
      const ath = base64url.encode(createHash('sha256').update(accessToken).digest());
      if (payload.ath !== ath) {
        throw new InvalidDpopProof('DPoP proof ath mismatch');
      }
    }
  } catch (err) {
    if (err instanceof InvalidDpopProof) {
      throw err;
    }
    throw new InvalidDpopProof('invalid DPoP key binding', err.message);
  }

  const thumbprint = await calculateJwkThumbprint(protectedHeader.jwk);

  return { thumbprint, jti: payload.jti, iat: payload.iat };
};
