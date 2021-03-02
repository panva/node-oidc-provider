const { default: jwtVerify } = require('jose/jwt/verify'); // eslint-disable-line import/no-unresolved
const { default: EmbeddedJWK } = require('jose/jwk/embedded'); // eslint-disable-line import/no-unresolved
const { default: calculateThumbprint } = require('jose/jwk/thumbprint'); // eslint-disable-line import/no-unresolved

const { InvalidDpopProof } = require('./errors');
const instance = require('./weak_cache');

module.exports = async (ctx) => {
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

    // TODO: allow trailing slash to be added/omitted at will,
    // see https://github.com/danielfett/draft-dpop/issues/49
    if (payload.htu !== ctx.oidc.urlFor(ctx.oidc.route)) {
      throw new Error('htu mismatch');
    }

    const thumbprint = await calculateThumbprint(jwk);

    return { thumbprint, jti: payload.jti, iat: payload.iat };
  } catch (err) {
    throw new InvalidDpopProof('invalid DPoP key binding', err.message);
  }
};
