const { InvalidRequestError, InvalidClientError } = require('../helpers/errors');
const instance = require('../helpers/weak_cache');
const JWT = require('../helpers/jwt');

module.exports = function getTokenJwtAuth(provider, endpoint) {
  return async function tokenJwtAuth(ctx, keystore, algorithms) {
    const uniqueCheck = instance(provider).configuration('uniqueness');
    const endpointUri = ctx.oidc.urlFor(endpoint);

    ctx.assert(ctx.oidc.params.client_assertion,
      new InvalidRequestError('client_assertion must be provided'));

    ctx.assert(ctx.oidc.params.client_assertion_type ===
      'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', new InvalidRequestError(
        'client_assertion_type must have value ' +
        'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'));

    const decoded = (() => {
      try {
        return JWT.decode(ctx.oidc.params.client_assertion);
      } catch (err) {
        return ctx.throw(new InvalidRequestError('client_assertion could not be decoded'));
      }
    })();

    const { header, payload } = decoded;

    ctx.assert(payload && header, new InvalidRequestError(
      'could not parse client_assertion as valid JWT'));

    ctx.assert(algorithms.indexOf(header.alg) !== -1,
      new InvalidRequestError('alg mismatch'));

    ctx.assert(payload.exp, new InvalidRequestError(
      'expiration must be specified in the client_assertion JWT'));

    ctx.assert(payload.jti, new InvalidRequestError(
      'unique jti (JWT ID) must be provided in the client_assertion JWT'));

    ctx.assert(payload.iss, new InvalidRequestError(
      'iss (JWT issuer) must be provided in the client_assertion JWT'));

    ctx.assert(payload.iss === ctx.oidc.client.clientId,
      new InvalidRequestError('issuer (iss) must be the client id'));

    ctx.assert(payload.aud, new InvalidRequestError(
      'aud (JWT audience) must be provided in the client_assertion JWT'));

    if (Array.isArray(payload.aud)) {
      ctx.assert(payload.aud.indexOf(endpointUri) !== -1, new InvalidRequestError(
        'list of audience (aud) must include the endpoint url'));
    } else {
      ctx.assert(payload.aud === endpointUri, new InvalidRequestError(
        'audience (aud) must equal the endpoint url'));
    }

    ctx.assert(payload.sub, new InvalidRequestError(
      'sub (JWT subject) must be provided in the client_assertion JWT'));

    ctx.assert(payload.sub === ctx.oidc.client.clientId,
      new InvalidRequestError('sub (JWT subject) must be the client id'));

    const unique = await uniqueCheck(ctx, payload.jti, payload.exp);
    ctx.assert(unique, new InvalidRequestError('jwt-bearer tokens must only be used once'));

    try {
      await JWT.verify(ctx.oidc.params.client_assertion, keystore, {
        audience: endpointUri,
        issuer: ctx.oidc.client.clientId,
      });
    } catch (err) {
      ctx.throw(new InvalidClientError(err.message));
    }
  };
};
