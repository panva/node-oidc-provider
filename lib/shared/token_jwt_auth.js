const { InvalidClientAuth } = require('../helpers/errors');
const instance = require('../helpers/weak_cache');
const JWT = require('../helpers/jwt');

module.exports = function getTokenJwtAuth(provider, endpoint) {
  return async function tokenJwtAuth(ctx, keystore, algorithms) {
    // Interoperability
    const acceptedAud = new Set([provider.issuer, ctx.oidc.urlFor('token')]);
    if (endpoint !== 'token') {
      acceptedAud.add(ctx.oidc.urlFor(endpoint));
    }

    const { header, payload } = JWT.decode(ctx.oidc.params.client_assertion);

    if (!algorithms.includes(header.alg)) {
      throw new InvalidClientAuth('alg mismatch');
    }

    if (!payload.exp) {
      throw new InvalidClientAuth('expiration must be specified in the client_assertion JWT');
    }

    if (!payload.jti) {
      throw new InvalidClientAuth('unique jti (JWT ID) must be provided in the client_assertion JWT');
    }

    if (!payload.iss) {
      throw new InvalidClientAuth('iss (JWT issuer) must be provided in the client_assertion JWT');
    }

    if (payload.iss !== ctx.oidc.client.clientId) {
      throw new InvalidClientAuth('issuer (iss) must be the client id');
    }

    if (!payload.aud) {
      throw new InvalidClientAuth('aud (JWT audience) must be provided in the client_assertion JWT');
    }

    if (Array.isArray(payload.aud)) {
      if (!payload.aud.some((aud) => acceptedAud.has(aud))) {
        throw new InvalidClientAuth('list of audience (aud) must include the endpoint url, issuer identifier or token endpoint url');
      }
    } else if (!acceptedAud.has(payload.aud)) {
      throw new InvalidClientAuth('audience (aud) must equal the endpoint url, issuer identifier or token endpoint url');
    }

    try {
      await JWT.verify(ctx.oidc.params.client_assertion, keystore, {
        clockTolerance: instance(provider).configuration('clockTolerance'),
        ignoreAzp: true,
      });
    } catch (err) {
      throw new InvalidClientAuth(err.message);
    }

    const unique = await provider.ReplayDetection.unique(payload.iss, payload.jti, payload.exp);

    if (!unique) {
      throw new InvalidClientAuth('client assertion tokens must only be used once');
    }
  };
};
