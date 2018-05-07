const { InvalidClientAuth } = require('../helpers/errors');
const instance = require('../helpers/weak_cache');
const JWT = require('../helpers/jwt');

module.exports = function getTokenJwtAuth(provider, endpoint) {
  return async function tokenJwtAuth(ctx, keystore, algorithms) {
    const uniqueCheck = instance(provider).configuration('uniqueness');
    const endpointUri = ctx.oidc.urlFor(endpoint);

    const { header, payload } = JWT.decode(ctx.oidc.params.client_assertion);

    if (!algorithms.includes(header.alg)) {
      ctx.throw(new InvalidClientAuth('alg mismatch'));
    }

    if (!payload.exp) {
      ctx.throw(new InvalidClientAuth('expiration must be specified in the client_assertion JWT'));
    }

    if (!payload.jti) {
      ctx.throw(new InvalidClientAuth('unique jti (JWT ID) must be provided in the client_assertion JWT'));
    }

    if (!payload.iss) {
      ctx.throw(new InvalidClientAuth('iss (JWT issuer) must be provided in the client_assertion JWT'));
    }

    if (payload.iss !== ctx.oidc.client.clientId) {
      ctx.throw(new InvalidClientAuth('issuer (iss) must be the client id'));
    }

    if (!payload.aud) {
      ctx.throw(new InvalidClientAuth('aud (JWT audience) must be provided in the client_assertion JWT'));
    }

    if (Array.isArray(payload.aud)) {
      if (!payload.aud.includes(endpointUri)) {
        ctx.throw(new InvalidClientAuth('list of audience (aud) must include the endpoint url'));
      }
    } else if (payload.aud !== endpointUri) {
      ctx.throw(new InvalidClientAuth('audience (aud) must equal the endpoint url'));
    }

    const unique = await uniqueCheck(ctx, payload.jti, payload.exp);

    if (!unique) {
      ctx.throw(new InvalidClientAuth('jwt-bearer tokens must only be used once'));
    }

    try {
      await JWT.verify(ctx.oidc.params.client_assertion, keystore, {
        audience: endpointUri,
        issuer: ctx.oidc.client.clientId,
        clockTolerance: instance(provider).configuration('clockTolerance'),
      });
    } catch (err) {
      ctx.throw(new InvalidClientAuth(err.message));
    }
  };
};
